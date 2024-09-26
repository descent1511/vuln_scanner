from celery import shared_task
from ..telegram_bot import TelegramBot  # Import the Telegram bot class
import time
import xml.etree.ElementTree as ET  # For parsing XML responses
import os
from django.utils import timezone
from ..services.gvm import ssh_connect  # Function for establishing SSH connection with OpenVAS
import requests
from ..services.translator import translate  # Import translation service
import re
import uuid

# Load backend IP and port from environment variables
backend_ip = os.getenv('BACKEND_IP')
backend_port = os.getenv('BACKEND_PORT', '8000')

# Shared Celery task to monitor scan task completion
@shared_task
def wait_for_task_completion(task_id):
    # Establish SSH connection
    ssh_client, error = ssh_connect()
    if error:
        raise Exception(f"SSH connection failed: {error}")
    
    # Retrieve GMP credentials from environment variables
    gmp_username = os.getenv('GMP_USERNAME', 'default_username')
    gmp_password = os.getenv('GMP_PASSWORD', 'default_password')

    # Command to get task status using gvm-cli
    command = f"""
        gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
        "<get_tasks task_id='{task_id}'/>"
    """
    # Generate a unique scan history ID
    scan_history_id = str(uuid.uuid4())
    try:
        # Create a new scan history entry via the API
        response = requests.post(f"http://{backend_ip}:{backend_port}/scan-history/", json={"task": task_id,"scan_id":scan_history_id})
        if response.status_code != 201:
            raise Exception(f"Failed to create scan history. Status code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"An error occurred while making the request: {e}")
    
    # Loop until the scan task completes
    while True:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        task_status_output = stdout.read().decode()
        task_status_error = stderr.read().decode()

        if task_status_error:
            raise Exception(f"Error checking task status: {task_status_error}")

        try:
            # Parse XML response to get the task status
            root = ET.fromstring(task_status_output)
            status_element = root.find(".//status")
            task_status = status_element.text if status_element is not None else None
        except ET.ParseError as e:
            raise Exception(f"Error parsing task status XML: {str(e)}")

        if task_status in ['Stopped', 'Failed', 'Done']:
            break

        time.sleep(30)  # Wait 30 seconds before re-checking

    # Fetch the report ID once the task completes
    report_id = get_report_id(task_id, ssh_client, gmp_username, gmp_password)
    send_vulnerabilities_to_telegram(report_id, ssh_client, gmp_username, gmp_password, task_id, scan_history_id,task_status)
    
    ssh_client.close()  # Close the SSH connection

# Helper function to get the report ID of a completed scan
def get_report_id(task_id, ssh_client, gmp_username, gmp_password):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_tasks task_id='{task_id}'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    report_output = stdout.read().decode()
    report_error = stderr.read().decode()

    if report_error:
        raise Exception(f"Error getting report: {report_error}")

    try:
        report_id = ET.fromstring(report_output).find('.//report').attrib['id']
    except ET.ParseError as e:
        raise Exception(f"Error parsing report XML: {str(e)}")
    except AttributeError:
        raise Exception(f"Could not find report ID in the task output")

    return report_id

# Function to extract vulnerabilities from the report and send alerts via Telegram
def send_vulnerabilities_to_telegram(report_id, ssh_client, gmp_username, gmp_password, task_id, scan_history_id ,task_status):
    backend_ip = os.getenv('BACKEND_IP')
    backend_port = os.getenv('BACKEND_PORT', '8000')
    
    # Command to get the detailed report content
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_reports report_id='{report_id}' ignore_pagination='1' details='1' apply_overrides='0' levels='hml' rows='100' min_qod='70' first='1' sort-reverse='severity'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    report_content_output = stdout.read().decode()
    report_content_error = stderr.read().decode()
    
    if report_content_error:
        raise Exception(f"Error getting report content: {report_content_error}")

    try:
        root = ET.fromstring(report_content_output)
        vulnerabilities = root.findall('.//results/result')
        
      
            
        cpe_entries = []
        os_info = None
        
        # Extract CPE entries and operating system information
        for elem in root.iter():
            if elem.text and '|cpe:' in elem.text:
                cpe_entry = elem.text.strip().split('|', 1)[-1]
                matches = re.findall(r'cpe:[^\n]+', cpe_entry)
                cpe_entries.extend(matches)

        # Extract OS information from vulnerability descriptions
        for result in vulnerabilities:
            description = result.find(".//description").text
            if description:
                os_match = re.search(r"OS:\s*(.*?)\n", description)
                if os_match:
                    os_info = os_match.group(1).strip()
                    break

        vulnerability_list = []
        cve_list = []
        host_list = []
        port_list = []

        # Extract high-severity vulnerabilities and related details
        for vulnerability in vulnerabilities:
            severity = vulnerability.find("threat").text
            if severity == 'High': 
                name = vulnerability.find("name").text
                host = vulnerability.find("host").text if vulnerability.find("host") is not None else "Unknown"
                port = vulnerability.find("port").text if vulnerability.find("port") is not None else "Unknown"
                
                if host not in host_list:
                    host_list.append(host)
                if port not in port_list:
                    port_list.append(port)
                
                # Extract CVE references
                references = vulnerability.findall(".//refs/ref")
                for ref in references:
                    if ref.attrib.get('type') == 'cve':
                        cve_id = ref.attrib.get('id')
                        if cve_id and cve_id not in cve_list:
                            cve_list.append(cve_id)
                
                vulnerability_list.append(name)

        # Remove duplicate entries
        cpe_entries = list(set(cpe_entries))
        host_list = list(set(host_list))
        port_list = list(set(port_list))
        cve_list = list(set(cve_list))
        vulnerability_list = list(set(vulnerability_list))

    except ET.ParseError as e:
        raise Exception(f"Error parsing report XML: {str(e)}")

    # Prepare data for updating scan history
    scan_history_data = {
        "vulnerabilities": vulnerability_list,
        "hosts": host_list,
        "ports": port_list,
        "applications": cpe_entries,
        "operating_system": os_info if os_info else "Unknown",
        "cve_names": cve_list,
        "end_time": timezone.now().isoformat(),
        "status": task_status
    }
    print(scan_history_data)
    try:
        # Update scan history via API
        response = requests.patch(f"http://{backend_ip}:{backend_port}/scan-history/{scan_history_id}/", json=scan_history_data)
        response.raise_for_status() 
        scan_history_data = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to patch scan history data: {e}")

    # Fetch Telegram users to send alerts
    response = requests.get(f"http://{backend_ip}:{backend_port}/users/")
    response.raise_for_status()  
    telegram_users = response.json()

    # Fetch task details
    response = requests.get(f"http://{backend_ip}:{backend_port}/tasks/{task_id}/")
    response.raise_for_status()  
    task = response.json()
    bot = TelegramBot()  # Initialize Telegram bot

    # Create a message template
    message_template = """
    🚨 **Vulnerability Alert Report** 🚨

    **{target_type}:** `{target}`  
    {operating_system}

    🔍 **Detected Vulnerabilities:**  
    {vulnerabilities}

    💻 **Affected Hosts:**  
    {hosts}

    🔌 **Open Ports:**  
    {ports}

    🛠️ **Detected Applications:**  
    {applications}

    🛑 **Related CVEs:**  
    {cve_names}

    ⚠️ Please review and take action accordingly.
    """

    # Format the message using the collected data
    message = message_template.format(
        target_type=task['target']['value_type'],
        target=task['target']['value'],
        start_time=scan_history_data['start_time'],
        vulnerabilities="\n".join(scan_history_data['vulnerabilities']),
        hosts="\n".join(scan_history_data['hosts']),
        ports="\n".join(scan_history_data['ports']),
        applications="\n".join(scan_history_data['applications']),
        operating_system=scan_history_data['operating_system'],
        cve_names="\n".join(scan_history_data['cve_names']),
    )

    # Send message to all Telegram users
    for telegram_user in telegram_users:
        if telegram_user['language'] == 'vi':  # Translate if the user prefers Vietnamese
            translated_message = translate(message)
            bot.send_message(telegram_user['telegram_id'], translated_message)
        else:
            bot.send_message(telegram_user['telegram_id'], message)  # Send message in English
