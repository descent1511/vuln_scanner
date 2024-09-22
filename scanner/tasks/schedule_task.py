import requests
from datetime import datetime

import os
from celery import shared_task
@shared_task
def check_targets():
    now = datetime.now()
    
    backend_ip = os.getenv('BACKEND_IP')
    backend_port = os.getenv('BACKEND_PORT', '8000')

    try:
        schedule_targets = requests.get(f"http://{backend_ip}:{backend_port}/schedules/").json()
    except requests.RequestException as e:
        print(f"Failed to retrieve schedule targets: {e}")
        return

    print(schedule_targets)
    for schedule_target in schedule_targets:
        interval = schedule_target['interval']
        if schedule_target['last_run'] is not None : 
            print((now -datetime.strptime(schedule_target['last_run'], "%Y-%m-%dT%H:%M:%S.%fZ") ).total_seconds())
        if schedule_target['last_run'] is None or (now -datetime.strptime(schedule_target['last_run'], "%Y-%m-%dT%H:%M:%S.%fZ") ).total_seconds() >= interval:
            value = schedule_target['value']
            scan_type = schedule_target['scan_type']

            if scan_type == 'spiderfoot':
                crawler_payload = {
                    "value": value
                }
                try:
                    response = requests.post(f"http://{backend_ip}:{backend_port}/crawlers/", json=crawler_payload)
                    response.raise_for_status()
                    print(f"SpiderFoot crawler started for value '{value}'")
                except requests.RequestException as e:
                    print(f"Failed to create SpiderFoot crawler for value '{value}': {e}")

            elif scan_type == 'openvas':
                task_payload = {
                    "value": value
                }
                try:
                    response = requests.post(f"http://{backend_ip}:{backend_port}/tasks/", json=task_payload)
                    response.raise_for_status()
                    print(f"OpenVAS scan started for value '{value}'")
                except requests.RequestException as e:
                    print(f"Failed to create OpenVAS task for value '{value}': {e}")

            try:
                update_url = f"http://{backend_ip}:{backend_port}/schedules/{schedule_target['id']}/"
                update_payload = {
                    "last_run": now.isoformat() 
                }
                update_response = requests.patch(update_url, json=update_payload)
                update_response.raise_for_status()
                print(f"Updated last_run for schedule_target '{schedule_target['id']}'")
            except requests.RequestException as e:
                print(f"Failed to update last_run for schedule_target '{schedule_target['id']}': {e}")
