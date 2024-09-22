import os
import requests
import json

# Load environment variables
SPIDERFOOT_IP = os.getenv("SPIDERFOOT_IP", "171.254.93.233")
SPIDERFOOT_PORT = os.getenv("SPIDERFOOT_PORT", "5001")
USERNAME = os.getenv("SPIDERFOOT_USERNAME", "")
PASSWORD = os.getenv("SPIDERFOOT_PASSWORD", "")

BASE_URL = f"http://{SPIDERFOOT_IP}:{SPIDERFOOT_PORT}"

def create_crawler(post=None):
    start_scan_url = f"{BASE_URL}/startscan/"
    if not post or not isinstance(post, dict):
        raise ValueError("Invalid data provided for the scan")

    headers = {
        "User-agent": "SpiderFoot-CLI/4.0.0",
        "Accept": "application/json"
    }

    try:
        print(f"Posting data to: {start_scan_url}")
        response = requests.post(
            start_scan_url,
            headers=headers,
            verify=False,
            auth=requests.auth.HTTPDigestAuth(USERNAME, PASSWORD),
            data=post  
        )

        print(f"Response: {response}")
        if response.status_code == requests.codes.ok:
            response_data = json.loads(response.text)
            if response_data[0] == "SUCCESS":
                scan_id = response_data[1]
                print(f"Successfully initiated scan. Scan ID: {scan_id}")
                return scan_id
            else:
                raise RuntimeError(f"Failed to start scan: {response_data[1]}")
        else:
            response.raise_for_status()

    except requests.RequestException as e:
        raise RuntimeError(f"Failed communicating with server: {e}")

