import requests  # Import requests for making HTTP requests
from datetime import datetime  # Import datetime for handling date and time operations
import os
from celery import shared_task  # Import shared_task to define a Celery task

# Define a shared Celery task to check target schedules
@shared_task
def check_targets():
    # Get the current time
    now = datetime.now()
    
    # Retrieve backend IP and port from environment variables
    backend_ip = os.getenv('BACKEND_IP')
    backend_port = os.getenv('BACKEND_PORT', '8000')

    try:
        # Fetch the list of scheduled targets from the backend
        schedule_targets = requests.get(f"http://{backend_ip}:{backend_port}/schedules/").json()
    except requests.RequestException as e:
        print(f"Failed to retrieve schedule targets: {e}")
        return

    print(schedule_targets)
    # Iterate over each scheduled target
    for schedule_target in schedule_targets:
        interval = schedule_target['interval']  # Get the interval in seconds

        # Check if the task has ever run or if the interval has passed
        if schedule_target['last_run'] is not None:
            print((now - datetime.strptime(schedule_target['last_run'], "%Y-%m-%dT%H:%M:%S.%fZ")).total_seconds())

        # Proceed if it's the first run or if enough time has passed since the last run
        if schedule_target['last_run'] is None or (now - datetime.strptime(schedule_target['last_run'], "%Y-%m-%dT%H:%M:%S.%fZ")).total_seconds() >= interval:
            value = schedule_target['value']  # Get the value to scan (e.g., IP address or domain)
            scan_type = schedule_target['scan_type']  # Get the scan type ('spiderfoot' or 'openvas')

            # Handle SpiderFoot scans
            if scan_type == 'spiderfoot':
                crawler_payload = {
                    "value": value
                }
                try:
                    # Send a POST request to initiate a SpiderFoot crawler
                    response = requests.post(f"http://{backend_ip}:{backend_port}/crawlers/", json=crawler_payload)
                    response.raise_for_status()
                    print(f"SpiderFoot crawler started for value '{value}'")
                except requests.RequestException as e:
                    print(f"Failed to create SpiderFoot crawler for value '{value}': {e}")

            # Handle OpenVAS scans
            elif scan_type == 'openvas':
                task_payload = {
                    "value": value
                }
                try:
                    # Send a POST request to initiate an OpenVAS task
                    response = requests.post(f"http://{backend_ip}:{backend_port}/tasks/", json=task_payload)
                    response.raise_for_status()
                    print(f"OpenVAS scan started for value '{value}'")
                except requests.RequestException as e:
                    print(f"Failed to create OpenVAS task for value '{value}': {e}")

            # Update the 'last_run' timestamp for the schedule target
            try:
                update_url = f"http://{backend_ip}:{backend_port}/schedules/{schedule_target['id']}/"
                update_payload = {
                    "last_run": now.isoformat()  # Update the last_run with the current time in ISO format
                }
                update_response = requests.patch(update_url, json=update_payload)
                update_response.raise_for_status()
                print(f"Updated last_run for schedule_target '{schedule_target['id']}'")
            except requests.RequestException as e:
                print(f"Failed to update last_run for schedule_target '{schedule_target['id']}': {e}")
