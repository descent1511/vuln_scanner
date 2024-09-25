from celery import shared_task  # Import shared_task to define a Celery task
from ..telegram_bot import TelegramBot  # Import the Telegram bot class
from django.utils import timezone  # Import timezone for time handling
import os
import requests  # Import requests for making HTTP requests
from ..services.translator import translate  # Import translation service (not used in this code)
import time

# Define a shared Celery task to wait for the SpiderFoot crawler to complete
@shared_task
def wait_for_crawler_complete(scan_id):
    # Retrieve SpiderFoot and backend IP/port from environment variables
    spiderfoot_ip = os.getenv('SPIDERFOOT_IP')
    spiderfoot_port = os.getenv('SPIDERFOOT_PORT', '5001')
    backend_ip = os.getenv('BACKEND_IP')
    backend_port = os.getenv('BACKEND_PORT', '8000')
    
    # Loop until the scan is no longer running
    while True:
        try:
            # Fetch the status of the SpiderFoot scan
            response = requests.get(f"http://{spiderfoot_ip}:{spiderfoot_port}/scanopts", params={'id': scan_id})
            response.raise_for_status()  # Raise an error for HTTP errors
            data = response.json()

            scan_status = data['meta'][5]  # Extract the scan status
            end_time = data['meta'][4] if scan_status != "RUNNING" and scan_status != "STARTING" else None
            print(scan_status)

            # Exit the loop if the scan is completed
            if scan_status != "RUNNING" and scan_status != "STARTING":
                update_data = {
                    'status': scan_status,
                    'end_time': end_time
                }
                
                try:
                    # Update the backend with the scan's completion status
                    response = requests.patch(f"http://{backend_ip}:{backend_port}/crawlers/{scan_id}/", json=update_data)
                    response.raise_for_status()
                except requests.RequestException as e:
                    raise RuntimeError(f"Failed to update Crawler status: {e}")

                break  # Exit the loop as the scan is complete

        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch scan status: {e}")

        # Wait for 30 seconds before checking the status again
        time.sleep(30)

    # If the scan completed, handle correlations and send notifications
    try:
        correlation_api_url = f"http://{spiderfoot_ip}:{spiderfoot_port}/scancorrelations?id={scan_id}"
        response = requests.get(correlation_api_url)
        response.raise_for_status()
        correlations = response.json()

        # Count the number of high or critical threats
        num_threats = len([corr for corr in correlations if corr[3] in ("HIGH", "CRITICAL")])
        try:
            if num_threats > 0:
                # Retrieve crawler information from the backend
                response = requests.get(f"http://{backend_ip}:{backend_port}/crawlers/{scan_id}/")
                response.raise_for_status()  
                crawler = response.json()
                
                # If the target value type is valid, initiate an OpenVAS scan
                if crawler['target']['value_type'] in ["domain_name", "ip_address", "hostname"]:
                    task_response = requests.post(
                        f"http://{backend_ip}:{backend_port}/tasks/create_and_start_task/",
                        json={'value': crawler['target']['value']}
                    )
                    task_response.raise_for_status()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

        # Update the number of threats collected in the backend
        update_data['num_threats_collected'] = num_threats
        try:
            response = requests.patch(f"http://{backend_ip}:{backend_port}/crawlers/{scan_id}/", json=update_data)
            response.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to update Crawler with threats: {e}")

        # Store correlation data in the backend
        for correlation in correlations:
            correlation_data = {
                'crawler': scan_id,
                'correlation_id': correlation[0],
                'headline': correlation[1],
                'collection_type': correlation[2],
                'risk_level': correlation[3],
                'description': correlation[4],
                'detailed_info': correlation[5],
                'metadata': correlation[6],
                'occurrences': correlation[7]
            }
            try:
                response = requests.post(f"http://{backend_ip}:{backend_port}/correlations/", json=correlation_data)
                response.raise_for_status()
            except requests.RequestException as e:
                raise RuntimeError(f"Failed to create scan with openvas from spiderfoot: {e}")

        # Initialize the Telegram bot
        bot = TelegramBot()
        response = requests.get(f"http://{backend_ip}:{backend_port}/users/")
        response.raise_for_status()
        telegram_users = response.json()

        # Send alerts to all Telegram users about the correlations
        for correlation in correlations:
            correlation_id = correlation[0]
            headline = correlation[1]
            severity = correlation[3]
            description = correlation[5]

            # Send messages in the appropriate language for each user
            for telegram_user in telegram_users:
                language = telegram_user['language']
                
                if language == 'vi':
                    # Create a message in Vietnamese
                    message = (
                        f"🛡️ **Thông báo từ SpiderFoot**\n\n"
                        f"**ID:** `{correlation_id}`\n\n"
                        f"**Tiêu đề:** *{headline}*\n\n"
                        f"**Mức độ:** `{severity}`\n\n"
                        f"**Mô tả:**\n"
                        f"> {description}\n\n"
                        f"---\n"
                    )
                else:
                    # Create a message in English
                    message = (
                        f"🛡️ **SpiderFoot Correlation Alert**\n\n"
                        f"**ID:** `{correlation_id}`\n\n"
                        f"**Headline:** *{headline}*\n\n"
                        f"**Severity:** `{severity}`\n\n"
                        f"**Description:**\n"
                        f"> {description}\n\n"
                        f"---\n"
                    )

                # Send the message using the Telegram bot
                bot.send_message(telegram_user['telegram_id'], message)

    except Exception as e:
        raise RuntimeError(f"An error occurred while handling correlations: {e}")
