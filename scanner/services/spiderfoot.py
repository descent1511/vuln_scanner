import os
import requests  # Import the requests library for making HTTP requests
import json  # Import JSON for parsing responses

# Load environment variables
SPIDERFOOT_IP = os.getenv("SPIDERFOOT_IP", "171.254.93.233")  # Default SpiderFoot IP if not provided
SPIDERFOOT_PORT = os.getenv("SPIDERFOOT_PORT", "5001")  # Default SpiderFoot port if not provided
USERNAME = os.getenv("SPIDERFOOT_USERNAME", "")  # SpiderFoot username from environment variables
PASSWORD = os.getenv("SPIDERFOOT_PASSWORD", "")  # SpiderFoot password from environment variables

# Construct the base URL for SpiderFoot API
BASE_URL = f"http://{SPIDERFOOT_IP}:{SPIDERFOOT_PORT}"

# Function to create a crawler (SpiderFoot scan)
def create_crawler(post=None):
    start_scan_url = f"{BASE_URL}/startscan/"  # Endpoint to start a scan in SpiderFoot

    # Validate the input data
    if not post or not isinstance(post, dict):
        raise ValueError("Invalid data provided for the scan")  # Raise error if input data is invalid

    # Set HTTP headers for the request
    headers = {
        "User-agent": "SpiderFoot-CLI/4.0.0",  # Custom User-agent header
        "Accept": "application/json"  # Requesting JSON response
    }

    try:
        # Print the URL to which data will be posted
        print(f"Posting data to: {start_scan_url}")
        
        # Send a POST request to SpiderFoot to initiate the scan
        response = requests.post(
            start_scan_url,
            headers=headers,
            verify=False,  # Skipping SSL verification (use caution in production)
            auth=requests.auth.HTTPDigestAuth(USERNAME, PASSWORD),  # HTTP Digest Authentication
            data=post  # Data to be sent in the request body
        )

        print(f"Response: {response}")  # Log the response status

        # Check if the request was successful (HTTP status code 200)
        if response.status_code == requests.codes.ok:
            response_data = json.loads(response.text)  # Parse the response JSON data
            if response_data[0] == "SUCCESS":  # Check if the scan initiation was successful
                scan_id = response_data[1]  # Extract the scan ID
                print(f"Successfully initiated scan. Scan ID: {scan_id}")
                return scan_id  # Return the scan ID
            else:
                raise RuntimeError(f"Failed to start scan: {response_data[1]}")
        else:
            response.raise_for_status()  # Raise an HTTPError for non-success status codes

    except requests.RequestException as e:
        # Handle communication errors with the SpiderFoot server
        raise RuntimeError(f"Failed communicating with server: {e}")
