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
import datetime
from scanner.models import ScanHistory, Task, TelegramUser
from datetime import datetime, timedelta
from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
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
        # Tạo bản ghi ScanHistory trực tiếp bằng Django ORM thay vì API
        task_instance = Task.objects.get(task_id=task_id)
        scan_history = ScanHistory.objects.create(
            task=task_instance,
            scan_id=scan_history_id
        )
    except Exception as e:
        raise Exception(f"Failed to create scan history in database: {e}")
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

def escape_markdown(text):
    # Escape special characters: underscore, asterisk, backtick, and square brackets
    markdown_escape_chars = '_*`[]'
    for char in markdown_escape_chars:
        text = text.replace(char, f'\\{char}')
    return text

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
    end_time = timezone.now()
    # Prepare data for updating scan history
    scan_history_data = {
        "vulnerabilities": vulnerability_list,
        "hosts": host_list,
        "ports": port_list,
        "applications": cpe_entries,
        "operating_system": os_info if os_info else "Unknown",
        "cve_names": cve_list,
        "end_time": end_time.isoformat(),
        "status": task_status
    }
   
    try:
        with transaction.atomic():
            scan_history = ScanHistory.objects.get(scan_id=scan_history_id)
            for key, value in scan_history_data.items():
                setattr(scan_history, key, value)
            scan_history.save()  # Lưu lại các thay đổi
    except ObjectDoesNotExist:
        raise RuntimeError(f"ScanHistory with ID {scan_history_id} does not exist")
    except Exception as e:
        raise RuntimeError(f"Failed to update scan history data: {e}")

    # Fetch Telegram users để gửi thông báo
    try:
        telegram_users = TelegramUser.objects.all()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch telegram users: {e}")

    # Fetch task details từ Task model
    try:
        task = Task.objects.get(task_id=task_id)
    except ObjectDoesNotExist:
        raise RuntimeError(f"Task with ID {task_id} does not exist")
    except Exception as e:
        raise RuntimeError(f"Failed to fetch task details: {e}")
    bot = TelegramBot()  # Initialize Telegram bot
    
    end_time_with_offset = end_time + timedelta(hours=7)
    pdf_file_name = f"{task.target.value}-{end_time_with_offset.strftime('%Y%m%d_%H%M%S')}.pdf"
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_reports report_id='{report_id}' format_id='c402cc3e-b531-11e1-9163-406186ea4fc5' ignore_pagination='1' details='1' apply_overrides='0' levels='hml' rows='100' min_qod='70' first='1' sort-reverse='severity'/>" | grep -oP '(?<=</report_format>)[^<]+' | base64 -d > /home/ubuntu/report/{pdf_file_name} 
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()

    if exit_status:
        error_message = stderr.read().decode()
        raise Exception(f"Error executing command: {error_message}")

    # Create a message template for the Telegram alert
    message_template = """
    🚨 *Vulnerability Alert Report* 🚨

    *Target Type:* `domain`
    *Target:* `{target}`
    {operating_system}

    🔍 *Detected Vulnerabilities:*
    {vulnerabilities}

    💻 *Affected Hosts:*
    {hosts}

    🔌 *Open Ports:*
    {ports}

    🛠️ *Detected Applications:*
    {applications}

    🛑 *Related CVEs:*
    {cve_names}

    ⚠️ Please review and take action accordingly.
    """

    # Format the message using the collected data, applying the escape function
    message = message_template.format(
        target_type=escape_markdown(task.target.value_type),
        target=escape_markdown(task.target.value),
        operating_system=escape_markdown(scan_history_data['operating_system']),
        vulnerabilities="\n ".join(escape_markdown(v) for v in scan_history_data['vulnerabilities']),
        hosts="\n ".join(escape_markdown(host) for host in scan_history_data['hosts']),
        ports="\n ".join(escape_markdown(port) for port in scan_history_data['ports']),
        applications="\n ".join(escape_markdown(app) for app in scan_history_data['applications']),
        cve_names="\n ".join(escape_markdown(cve) for cve in scan_history_data['cve_names']),
    )


    # Send message to all Telegram users
    for telegram_user in telegram_users:
        if telegram_user.language == 'vi':  # Translate if the user prefers Vietnamese
            translated_message = translate(message)
            bot.send_message(telegram_user.telegram_id, message=translated_message, pdf_path=f"/home/ubuntu/report/{pdf_file_name}")  
        else:
            bot.send_message(telegram_user.telegram_id, message=message, pdf_path=f"/home/ubuntu/report/{pdf_file_name}")   # Send message in English
    if os.path.exists(f"/home/ubuntu/report/{pdf_file_name}"):
        try:
            os.remove(f"/home/ubuntu/report/{pdf_file_name}")
        except Exception as e:
            raise Exception(f"Error deleting file /home/ubuntu/report/{pdf_file_name}: {e}")



@shared_task
def update_and_fetch_cve_data():
    print("Running to Update CVE OpenVAS task...")

    ssh_client, error = ssh_connect()
    if error:
        raise Exception(f"SSH connection failed: {error}")
    
    # Retrieve GMP credentials from environment variables
    gmp_username = os.getenv('GMP_USERNAME', 'default_username')
    gmp_password = os.getenv('GMP_PASSWORD', 'default_password')

    # Update OpenVAS feeds
    update_command = ("sudo runuser -u gvm /usr/local/bin/greenbone-feed-sync")

    # Calculate the time exactly 1 hour ago
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    formatted_time = one_hour_ago.strftime("%Y-%m-%dT%H:%M:%S")

    # The command to execute to retrieve CVEs, using an exact date and time
    gvm_command = f"gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \"<get_info type='cve' filter='published>{formatted_time} and severity>7 and severity!=n/a'/>\""

    try:
        stdin, stdout, stderr = ssh_client.exec_command(update_command)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status :
            raise Exception(f"Update failed with exit status {exit_status}.")
        
        # Optional: Add a delay to ensure the update process is fully complete
        time.sleep(100)

        # Step 2: Execute the command to retrieve new CVEs
        stdin, stdout, stderr = ssh_client.exec_command(gvm_command)
        
        # Read the XML output
        xml_data = stdout.read().decode()
        
        # Parse the XML data
        root = ET.fromstring(xml_data)

        # Extract CVE entries
        cve_entries = []
        for info in root.findall('info'):
            cve_id = info.find('name').text if info.find('name') is not None else "N/A"
            severity = info.find('./cve/severity').text if info.find('./cve/severity') is not None else "N/A"
            cvss_vector = info.find('./cve/cvss_vector').text if info.find('./cve/cvss_vector') is not None else "N/A"
            description = info.find('./cve/description').text if info.find('./cve/description') is not None else "N/A"
            
            cve_entries.append({
                "CVE ID": cve_id,
                "Severity": severity,
                "CVSS Vector": cvss_vector,
                "Description": description
            })
            # Fetch Telegram users để gửi thông báo
        try:
            telegram_users = TelegramUser.objects.all()
        except Exception as e:
            raise RuntimeError(f"Failed to fetch telegram users: {e}")
        bot = TelegramBot() 
        # Display each CVE entry
        for entry in cve_entries:
            if entry['Severity'] == 'N/A':
                continue
            for user in telegram_users:
                telegram_message = (
                    f"⚠️ *New CVE Alert* ⚠️\n\n"
                    f"*CVE ID:* {escape_markdown(entry['CVE ID'])}\n"
                    f"*Severity:* {escape_markdown(entry['Severity'])}\n"
                    f"*CVSS Vector:* {escape_markdown(entry['CVSS Vector'])}\n"
                    f"*Description:* {escape_markdown(entry['Description'])}\n"
                )
        
                    # Send each CVE entry as a separate Telegram message
                bot.send_message(user.telegram_id, telegram_message)
                
    except Exception as e:
        raise Exception(f"An error occurred: {e}")
    finally:
        ssh_client.close()