from celery import shared_task
import requests
from celery.schedules import crontab,timedelta
from vuln_scanner.celery import app


@shared_task
def run_spiderfoot_task():
    targets_url = 'http://127.0.0.1:8000/targets/'
    crawlers_url = 'http://127.0.0.1:8000/crawlers/'

    try:
        response = requests.get(targets_url)
        if response.status_code == 200:
            targets = response.json()

            for target in targets:
                # if target['hosts'] in hosts_to_check:
                target_id = target['target_id'] 
                print(target_id)
                data = {
                    "target_id": target_id
                }
                    # Gửi request POST tới API crawlers
                crawler_response = requests.post(crawlers_url, json=data)
                print(crawler_response)
                if crawler_response.status_code == 200:
                    print(f'Successfully crawled target {target_id}: {crawler_response.json()}')
                else:
                    print(f'Failed to crawl target {target_id}: {crawler_response.status_code}')
        else:
            print(f'Failed to get targets: {response.status_code}')
    except requests.RequestException as e:
        print(f'Error fetching targets or crawling: {str(e)}')

    return "API calls complete"


# from celery import shared_task
# from celery.utils.log import get_task_logger

# logger = get_task_logger(__name__)

# @shared_task
# def run_spiderfoot_task():
#     logger.info('SpiderFoot task is running')
#     # Add your SpiderFoot scan logic here
#     # Call the SpiderFoot API, process data, etc.
#     pass

# @shared_task
# def run_openvas_task():
#     logger.info('OpenVAS task is running')
#     # Add your OpenVAS scan logic here
#     # Call the OpenVAS API, process data, etc.
#     pass
