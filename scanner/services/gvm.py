import subprocess
import xml.etree.ElementTree as ET  # Import XML library for parsing XML responses
import paramiko  # Import Paramiko for SSH connections
from dotenv import load_dotenv  # Import dotenv to load environment variables
import time
import os

# Load environment variables from the .env file
load_dotenv()

# Retrieve environment variables
remote_host = os.environ.get('OPENVAS_HOST', 'default_host')  # Remote host for OpenVAS
remote_port = int(os.environ.get('OPENVAS_PORT', 22))  # Remote port (default is 22)
username = os.environ.get('SSH_USERNAME', 'default_user')  # SSH username
password = os.environ.get('SSH_PASSWORD', 'default_password')  # SSH password
gmp_username = os.getenv('GMP_USERNAME', 'default_username')  # GMP username
gmp_password = os.getenv('GMP_PASSWORD', 'default_password')  # GMP password
socket_path = '/run/gvmd/gvmd.sock'  # Path to the OpenVAS socket

# Function to establish an SSH connection using Paramiko
def ssh_connect():
    global ssh_client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically add host key
    try:
        ssh_client.connect(hostname=remote_host, port=remote_port, username=username, password=password)
        return ssh_client, None  # Return SSH client if successful
    except paramiko.AuthenticationException:
        return None, "Authentication failed, please verify your credentials"
    except paramiko.SSHException as sshException:
        return None, f"Unable to establish SSH connection: {sshException}"
    except Exception as e:
        return None, f"Exception in connecting to the server: {e}"

# Function to create a target in OpenVAS
def create_target(target_name, hosts, port_list):
    print(gmp_username, gmp_password)  # Print GMP credentials (remove this in production)
    # Command to create the target using gvm-cli
    command = f"gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} " \
              f"socket --socketpath {socket_path} " \
              f"--xml \"<create_target><name>{target_name}</name><hosts>{hosts}</hosts>" \
              f"<port_list id='{port_list}'></port_list></create_target>\""
    
    stdin, stdout, stderr = ssh_client.exec_command(command)  # Execute the command over SSH
    content_output = stdout.read().decode()
    content_error = stderr.read().decode()

    if content_error:
        raise Exception("Failed to create target")
    else:
        return parse_gvm_id(content_output)  # Extract and return the ID of the created target

# Function to create a scan task in OpenVAS
def create_task(target_id, scan_config, task_name, scanner):
    command = (
        f"gvm-cli --gmp-username {gmp_username} --gmp-password {gmp_password} "
        f"socket --socketpath {socket_path} "
        f"--xml \"<create_task><name>{task_name}</name>"
        f"<config id='{scan_config}'/>"
        f"<target id='{target_id}'/>"
        f"<scanner id='{scanner}'/></create_task>\""
    )

    stdin, stdout, stderr = ssh_client.exec_command(command)
    content_output = stdout.read().decode()
    content_error = stderr.read().decode()
    
    print(content_output)  # Print the output for debugging
    if content_error:
        raise Exception(f"Failed to create task: {content_error}")
    else:
        return parse_gvm_id(content_output)  # Return the created task's ID

# Function to start a scan task in OpenVAS
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
        return True  # Return True if the task started successfully

# Function to check the status of a scan task
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
        root = ET.fromstring(task_status_output)  # Parse the XML response
        status_element = root.find(".//status")
        task_status = status_element.text if status_element is not None else None
    except ET.ParseError as e:
        raise Exception(f"Error parsing task status XML: {str(e)}")
    return task_status  # Return the task status

# Function to get the report ID for a completed task
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
        return report_id  # Return the report ID

# Function to get the detailed report content from OpenVAS
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
    
    return report_content_output  # Return the report content

# Function to delete a scan task
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
        return True  # Return True if the task was deleted successfully

# Function to delete a target
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
        return True  # Return True if the target was deleted successfully

# Function to parse the ID from the GVM XML response
def parse_gvm_id(output):
    root = ET.fromstring(output)
    return root.attrib['id']  # Return the ID attribute
