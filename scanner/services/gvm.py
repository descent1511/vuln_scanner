import subprocess
import xml.etree.ElementTree as ET
import paramiko
from dotenv import load_dotenv
import time

import os
import time
load_dotenv()

remote_host = os.environ.get('OPENVAS_HOST', 'default_host')
remote_port = int(os.environ.get('OPENVAS_PORT', 22))
username = os.environ.get('SSH_USERNAME', 'default_user')
password = os.environ.get('SSH_PASSWORD', 'default_password')
gmp_username = os.getenv('GMP_USERNAME', 'default_username')
gmp_password = os.getenv('GMP_PASSWORD', 'default_password')
socket_path='/run/gvmd/gvmd.sock'

def ssh_connect():
    global ssh_client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(hostname=remote_host, port=remote_port, username=username, password=password)
        return ssh_client, None
    except paramiko.AuthenticationException:
        return None, "Authentication failed, please verify your credentials"
    except paramiko.SSHException as sshException:
        return None, f"Unable to establish SSH connection: {sshException}"
    except Exception as e:
        return None, f"Exception in connecting to the server: {e}"

def create_target(target_name, hosts, port_list):
    print(gmp_username,gmp_password)
    command = f"gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} " \
              f"socket --socketpath {socket_path} " \
              f"--xml \"<create_target><name>{target_name}</name><hosts>{hosts}</hosts>" \
              f"<port_list id='{port_list}'></port_list></create_target>\""
    # print(command)
    stdin, stdout, stderr = ssh_client.exec_command(command)
    # print(content_output)
    content_output = stdout.read().decode()
    content_error = stderr.read().decode()

    if content_error:
        raise Exception(f"Failed to create target")
    else:
        return parse_gvm_id(content_output)


def create_task(target_id, scan_config, task_name, scanner):
    command = (
        f"gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} "
        f"socket --socketpath {socket_path} "
        f"--xml \"<create_task><name>{task_name}</name>"
        f"<config id='{scan_config}'/>"
        f"<target id='{target_id}'/>"
        f"<scanner id='{scanner}'/></create_task>\""
    )

    # Execute the command via SSH
    stdin, stdout, stderr = ssh_client.exec_command(command)
    
    content_output = stdout.read().decode()
    content_error = stderr.read().decode()
    
    # Print output and check for errors
    print(content_output)
    if content_error:
        raise Exception(f"Failed to create task: {content_error}")
    else:
        return parse_gvm_id(content_output)


def start_task(task_id):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<start_task task_id='{task_id}'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    start_task_output = stdout.read().decode()
    start_task_error = stderr.read().decode()
    if start_task_error:
        raise Exception(f"Error starting task: {start_task_error}")
    else:
        return True

def get_task_status(task_id):

    command = f"""
        gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
        "<get_tasks task_id='{task_id}'/>"
        """
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
        raise Exception("Error parsing task status XML: {str(e)}")
    return task_status



def get_report_id(task_id):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_tasks task_id='{task_id}'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    report_output = stdout.read().decode()
    report_error = stderr.read().decode()
    report_id = ET.fromstring(report_output).find('.//report').attrib['id']
    if report_error:
        raise Exception(f"Error getting report: {report_error}")
    else:
        return report_id


def get_report_content(report_id):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<get_reports report_id='{report_id}' ignore_pagination='1' details='1' filter='levels=hmlg min_qod=0'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    report_content_output = stdout.read().decode()
    report_content_error = stderr.read().decode()

    if report_content_error:
        raise Exception(f"Error getting report content: {report_content_error}")
    
    return report_content_output

def delete_task(task_id):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<delete_task task_id='{task_id}'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    delete_task_output = stdout.read().decode()
    delete_task_error = stderr.read().decode()

    if delete_task_error:
        raise Exception(f"Error deleting task: {delete_task_error}")
    else:
        # print(f"Task {task_id} has been successfully deleted.")
        return True

def delete_target(target_id):
    command = f"""
    gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} socket --xml \\
    "<delete_target target_id='{target_id}'/>"
    """
    stdin, stdout, stderr = ssh_client.exec_command(command)
    delete_target_output = stdout.read().decode()
    delete_target_error = stderr.read().decode()

    if delete_target_error:
        raise Exception(f"Error deleting target: {delete_target_error}")
    else:
        return True


def parse_gvm_id(output):
    root = ET.fromstring(output)
    return root.attrib['id']


