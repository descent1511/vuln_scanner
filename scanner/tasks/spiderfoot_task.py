from celery import shared_task
from ..telegram_bot import TelegramBot
from django.utils import timezone
from ..services.gvm import ssh_connect
import os
import requests
from ..services.translator import translate

@shared_task
def run_spiderfoot_scan_task(ip_address):
    try:
        ssh_client, error = ssh_connect()
        if error:
            raise Exception(f"SSH connection failed: {error}")
        
        spiderfoot_script_path = os.getenv('SPIDERFOOT_SCRIPT_PATH')
        backend_ip = os.getenv('BACKEND_IP')
        backend_port = os.getenv('BACKEND_PORT', '8000')
        spiderfoot_ip = os.getenv('SPIDERFOOT_IP')
        spiderfoot_port = os.getenv('SPIDERFOOT_PORT', '5001')

        crawler_api_url = f"http://{backend_ip}:{backend_port}/crawlers/"
        correlation_api_url = f"http://{spiderfoot_ip}:{spiderfoot_port}/scancorrelations"

        command = (
            f'python3 {spiderfoot_script_path} -s {ip_address}'
        )
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        error_output = stderr.read().decode()
        last_lines = error_output.splitlines()[-2:]

        scan_id = None
        status = None

        for line in last_lines:
            if "Scan [" in line and "]" in line:
                scan_id = line.split("Scan [")[1].split("]")[0]
            if "Scan completed with status" in line:
                status = line.split("Scan completed with status ")[1]
        
        exit_status = stdout.channel.recv_exit_status()

        if scan_id and status:
            end_time = timezone.now().isoformat()   
            update_data = {
                'status': status,
                'end_time': end_time
            }
            try:
                response = requests.patch(f"{crawler_api_url}{scan_id}/", json=update_data)
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to update Crawler: {e}")

            if status == "FINISHED":
                response = requests.get(f"{correlation_api_url}?id={scan_id}")
                response.raise_for_status()
                correlations = response.json()

                num_threats = len([corr for corr in correlations if corr[3] in ("HIGH", "CRITICAL")])

                update_data['num_threats_collected'] = num_threats
                try:
                    response = requests.patch(f"{crawler_api_url}{scan_id}/", json=update_data)
                    response.raise_for_status()
                except requests.RequestException as e:
                    print(f"Failed to update Crawler with threats: {e}")

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
                        response = requests.post(f"{crawler_api_url}", json=correlation_data)
                        response.raise_for_status()
                    except requests.RequestException as e:
                        print(f"Failed to create Correlation: {e}")

                bot = TelegramBot()

                response = requests.get(f"http://{backend_ip}:{backend_port}/users/")
                response.raise_for_status()  
                telegram_users = response.json()

                for correlation in correlations:
                    correlation_id = correlation[0]
                    headline = correlation[1]
                    severity = correlation[3]
                    description = correlation[5]

                    for telegram_user in telegram_users:
                        language = telegram_user['language']

                        if language == 'vi':
                            message = (
                                f"🛡️ **Thông báo từ SpiderFoot**\n\n"
                                f"**ID:** `{correlation_id}`\n\n"
                                f"**Tiêu đề:** *{translate(headline)}*\n\n"
                                f"**Mức độ:** `{translate(severity)}`\n\n"
                                f"**Mô tả:**\n"
                                f"> {translate(description)}\n\n"
                                f"---\n"
                            )
                        else:
                            message = (
                                f"🛡️ **SpiderFoot Correlation Alert**\n\n"
                                f"**ID:** `{correlation_id}`\n\n"
                                f"**Headline:** *{headline}*\n\n"
                                f"**Severity:** `{severity}`\n\n"
                                f"**Description:**\n"
                                f"> {description}\n\n"
                                f"---\n"
                            )

                        bot.send_message(telegram_user['telegram_id'], message)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        ssh_client.close()
