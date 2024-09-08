from celery import shared_task
from .telegram_bot import TelegramBot
import time
import xml.etree.ElementTree as ET
import os
from django.utils import timezone
from googletrans import Translator
import subprocess
from .services.gvm import ssh_connect
import requests
from.services.translator import translate
from .models import SecurityAlert,Crawler,TelegramUser
@shared_task
def wait_for_task_completion(task_id):
    ssh_client, error = ssh_connect()
    if error:
        raise Exception(f"SSH connection failed: {error}")
    
    gmp_username = os.getenv('GMP_USERNAME', 'default_username')
    gmp_password = os.getenv('GMP_PASSWORD', 'default_password')

    command = f"""
        gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
        "<get_tasks task_id='{task_id}'/>"
    """
    
    while True:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        task_status_output = stdout.read().decode()
        task_status_error = stderr.read().decode()

        if task_status_error:
            raise Exception(f"Error checking task status: {task_status_error}")

        try:
            root = ET.fromstring(task_status_output)
            status_element = root.find(".//status")
            task_status = status_element.text if status_element is not None else None
        except ET.ParseError as e:
            raise Exception(f"Error parsing task status XML: {str(e)}")

        if task_status in ['Stopped', 'Failed', 'Done']:
            break

        time.sleep(30)  

    report_id = get_report_id(task_id, ssh_client, gmp_username, gmp_password)
    print(report_id)

    send_vulnerabilities_to_telegram(report_id, ssh_client, gmp_username, gmp_password)
    
    ssh_client.close()

    


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
def send_vulnerabilities_to_telegram(report_id, ssh_client, gmp_username, gmp_password):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_reports report_id='{report_id}' ignore_pagination='1' details='1' filter='levels=hmlg min_qod=0'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    report_content_output = stdout.read().decode()
    report_content_error = stderr.read().decode()
    
    if report_content_error:
        raise Exception(f"Error getting report content: {report_content_error}")
    
    print(report_content_output)  
    
    try:
        root = ET.fromstring(report_content_output)
        vulnerabilities = root.findall('.//results/result')
        
        if not vulnerabilities:
            raise Exception("No vulnerabilities found in the report.")

    except ET.ParseError as e:
        raise Exception(f"Error parsing report XML: {str(e)}")

    # # Collecting vulnerabilities data
    vulnerability_list = []
    # for vulnerability in vulnerabilities:
    #     severity = vulnerability.find("threat").text
    #     if severity in ['High', 'Medium']:
    #         name = vulnerability.find("name").text
    #         host = vulnerability.find("host").text if vulnerability.find("host") is not None else "Unknown"
    #         port = vulnerability.find("port").text if vulnerability.find("port") is not None else "Unknown"
    #         references = vulnerability.findall(".//refs/ref")[:3]
    #         reference_list = []
    for vulnerability in vulnerabilities:
        severity = vulnerability.find("threat").text
        if severity in ['High', 'Medium']:
            name = vulnerability.find("name").text
            host = vulnerability.find("host").text if vulnerability.find("host") is not None else "Unknown"
            hostname = vulnerability.find(".//hostname").text if vulnerability.find(".//hostname") is not None else "Unknown"
            port = vulnerability.find("port").text if vulnerability.find("port") is not None else "Unknown"
            
            original_threat = vulnerability.find("original_threat").text if vulnerability.find("original_threat") is not None else "Unknown"
            original_severity = vulnerability.find("original_severity").text if vulnerability.find("original_severity") is not None else "Unknown"
            modification_time = vulnerability.find("modification_time").text if vulnerability.find("modification_time") is not None else "Unknown"
            creation_time = vulnerability.find("creation_time").text if vulnerability.find("creation_time") is not None else "Unknown"
            nvt_oid = vulnerability.find(".//nvt").attrib['oid'] if vulnerability.find(".//nvt") is not None else "Unknown"
            cvss_base_score = vulnerability.find(".//cvss_base").text if vulnerability.find(".//cvss_base") is not None else "Unknown"
            severity_score = vulnerability.find(".//severity/score").text if vulnerability.find(".//severity/score") is not None else "Unknown"
            severity_origin = vulnerability.find(".//severity/origin").text if vulnerability.find(".//severity/origin") is not None else "Unknown"
            solution = vulnerability.find(".//solution").text.strip() if vulnerability.find(".//solution") is not None else "No solution provided"
            description = vulnerability.find(".//description").text.strip() if vulnerability.find(".//description") is not None else "No description provided"
            
            references = vulnerability.findall(".//refs/ref")[:3]
            reference_list = []
            for ref in references:
                if ref.attrib.get('type') == 'cve':
                    reference_list.append(f"- [CVE ID: {ref.attrib.get('id')}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={ref.attrib.get('id')})")
                elif ref.attrib.get('type') == 'url':
                    domain = ref.attrib.get('id').split('/')[2]
                    reference_list.append(f"- [Url: {domain}]({ref.attrib.get('id')})")

            reference_list = "\n".join(reference_list)
     
            vulnerability_list.append({
                'severity': severity,
                'name': name,
                'host': host,
                'hostname': hostname,
                'port': port,
                'original_threat': original_threat,
                'original_severity': original_severity,
                'modification_time': modification_time,
                'creation_time': creation_time,
                'nvt_oid': nvt_oid,
                'cvss_base_score': cvss_base_score,
                'severity_score': severity_score,
                'severity_origin': severity_origin,
                'solution': solution,
                'description': description,
                'references': reference_list
            })


            # Creating the security alert data
            security_alert_data = {
                'severity': severity,
                'name': name,
                'ip_address': host,
                'hostname': hostname,
                'port': port,
                'original_threat': original_threat,
                'original_severity': original_severity,
                'modification_time': modification_time,
                'creation_time': creation_time,
                'nvt_oid': nvt_oid,
                'cvss_base_score': cvss_base_score,
                'severity_score': severity_score,
                'severity_origin': severity_origin,
                'description': description,
                'solution': solution,
                'references': reference_list,
                'recommendation': "Please review the vulnerability and apply appropriate measures.",
                'status': 'Unresolved',
                'notified': True,
                'notification_sent_at': timezone.now().isoformat(),
                'notification_channel': 'Telegram',
                'owner': 'Viettel Cloud Security Team'
            }


            try:
                response = requests.post('http://127.0.0.1:8000/security-alerts/', json=security_alert_data)
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to send security alert data: {e}")

    # Fetching Telegram users
    response = requests.get("http://localhost:8000/users/")
    response.raise_for_status()  
    telegram_users = response.json()

    bot = TelegramBot()
    
    # Sending vulnerabilities to each user
    for telegram_user in telegram_users:
        language = telegram_user['language']

        for vulnerability in vulnerability_list:
            severity = vulnerability['severity']
            name = vulnerability['name']
            host = vulnerability['host']
            port = vulnerability['port']
            reference_list = vulnerability['references']

            if language == 'vi':
                message = (
                    f"**🛡 Phát hiện lỗ hổng bảo mật**\n\n"
                    f"**🔺 Mức độ:** `{translate(severity)}`\n\n"
                    f"**🔍 Tên:** `{translate(name)}`\n\n"
                    f"**🌐 Máy chủ:** `{host}`\n"
                    f"**🌍 Cổng:** `{port}`\n\n"
                    f"**🔗 Tham khảo:**\n{reference_list}\n"
                    f"\n------------------------------------\n"
                )
            else: 
                message = (
                    f"**🛡 Vulnerability Detected**\n\n"
                    f"**🔺 Severity:** `{severity}`\n\n"
                    f"**🔍 Name:** `{name}`\n\n"
                    f"**🌐 Host:** `{host}`\n"
                    f"**🌍 Port:** `{port}`\n\n"
                    f"**🔗 References:**\n{reference_list}\n"
                    f"\n------------------------------------\n"
                )

            bot.send_message(telegram_user['telegram_id'], message)


@shared_task
def run_nikto_scan(task_id, host):
    command = ["nikto", "-h", host, "-p", "1000"]
    result = subprocess.run(command, capture_output=True, text=True)

    # Get scan result from stdout
    scan_report = result.stdout

    # Initialize Telegram bot and send the scan result
    bot = TelegramBot()
    message = f"Task with ID {task_id} has finished.\n\nScan Report for {host}:\n{scan_report}"
    bot.send_message(message)



@shared_task
def run_spiderfoot_scan_task(ip_address):
    try:
        ssh_client, error = ssh_connect()
        if error:
            raise Exception(f"SSH connection failed: {error}")
        
        command = (
            'source /home/descent/Documents/spiderfoot/myenv/bin/activate && '
            f'python3 /home/descent/Documents/spiderfoot/sf.py -s {ip_address}'
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
                response = requests.patch(f"http://127.0.0.1:8000/crawlers/{scan_id}/", json=update_data)
                response.raise_for_status()
            except requests.RequestException as e:
                print(f"Failed to update Crawler: {e}")

            if status == "FINISHED":
                correlation_url = f"http://192.168.102.133:5001/scancorrelations?id={scan_id}"
                response = requests.get(correlation_url)
                response.raise_for_status()
                correlations = response.json()

                num_threats = len([corr for corr in correlations if corr[3] in ("HIGH", "CRITICAL")])

                # Gửi số lượng threats qua API
                update_data['num_threats_collected'] = num_threats
                try:
                    response = requests.patch(f"http://127.0.0.1:8000/crawlers/{scan_id}/", json=update_data)
                    response.raise_for_status()
                except requests.RequestException as e:
                    print(f"Failed to update Crawler with threats: {e}")

                # Create Correlations
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
                        response = requests.post(f"http://127.0.0.1:8000/correlations/", json=correlation_data)
                        response.raise_for_status()
                    except requests.RequestException as e:
                        print(f"Failed to create Correlation: {e}")

                bot = TelegramBot()

                response = requests.get("http://localhost:8000/users/")
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
