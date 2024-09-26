import time
from .serializers import (TargetSerializer, TaskSerializer, VulnerabilitySerializer, SecurityAlertSerializer,
                          CrawlerSerializer, CorrelationSerializer, TelegramUserSerializer, TargetScheduleSerializer,
                          ScanHistorySerializer)
from .models import (Target, PortList, Task, ScanConfig, Scanner, Vulnerability, SecurityAlert, Crawler, Correlation,
                     TelegramUser, TargetSchedule, ScanHistory)
from rest_framework import generics, viewsets, status
from django.utils.timezone import now
import xml.etree.ElementTree as ET
from .services.gvm import create_target, create_task, start_task, delete_task, delete_target
from rest_framework.response import Response
from rest_framework import viewsets
import requests
from rest_framework.decorators import action
from .tasks.openvas_task import wait_for_task_completion  # Celery task for monitoring OpenVAS scan completion
from .tasks.spiderfoot_task import wait_for_crawler_complete  # Celery task for monitoring SpiderFoot crawl completion
from rest_framework.views import APIView
import os
from .services.spiderfoot import create_crawler  # Function to initiate a SpiderFoot scan
from .services.check_input import validate_input  # Function to validate user input
from django_celery_beat.models import PeriodicTask, IntervalSchedule  # For periodic task scheduling
import uuid
from django.shortcuts import render


# View to render the threat intelligence scan page
def threat_intelligence_view(request):
    return render(request, 'scan.html')


# TargetViewSet handles operations related to scan targets
class TargetViewSet(viewsets.ModelViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer  

    # Create a new target
    def create(self, request, *args, **kwargs):
        input_data = request.data
        value = input_data.get('value')  # The target's value (IP/domain)
        
        port_list_option = input_data.get('port_list', PortList.IANA_ASSIGNED_TCP)  # Default port list option

        # Mapping port list options to UUIDs
        port_list_uuid_mapping = {
            'IANA_ASSIGNED_TCP': PortList.IANA_ASSIGNED_TCP,
            'ALL_IANA_ASSIGNED_TCP_UDP': PortList.ALL_IANA_ASSIGNED_TCP_UDP,
            'ALL_TCP_NMAP_TOP_100_UDP': PortList.ALL_TCP_NMAP_TOP_100_UDP,
        }

        port_list = port_list_uuid_mapping.get(port_list_option, PortList.IANA_ASSIGNED_TCP)
        value_type = validate_input(value)  # Validate the input value

        # Return error if invalid
        if value_type == "Invalid input":
            return Response({'error': 'Invalid value'}, status=status.HTTP_400_BAD_REQUEST)

        # Construct a target name
        target_name = value + '-' + port_list

        # Create target in OpenVAS
        if value_type in ["domain_name", "ip_address", "hostname"]:
            try:
                target_id = create_target(target_name, value, port_list)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            target_id = str(uuid.uuid4())  # Generate UUID if not OpenVAS-compatible

        # Prepare data to create the target in the database
        data = {
            'value': value,
            'port_list': port_list,
            'target_name': target_name,
            'value_type': value_type,
            'target_id': target_id
        }
        
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)  # Save target to DB
        headers = self.get_success_headers(serializer.data)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    # Destroy method to delete a target
    def destroy(self, request, *args, **kwargs):
        target = self.get_object()

        # Check if tasks exist for this target
        related_tasks = Task.objects.filter(target=target)
        if related_tasks.exists():
            return Response({'error': 'Cannot delete target because there are tasks associated with this target.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if crawlers exist for this target
        related_crawlers = Crawler.objects.filter(target=target)
        if related_crawlers.exists():
            return Response({'error': 'Cannot delete target because there are crawlers associated with this target.'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Delete target in OpenVAS and database
            delete_target(target.target_id)
            target.delete() 
        except Exception as e:
            return Response({'error': f"Failed to delete target: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': 'Target deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

    
# TaskViewSet to manage OpenVAS scan tasks
class TaskViewSet(viewsets.ModelViewSet):
    serializer_class = TaskSerializer
    queryset = Task.objects.all()
    # Create a new task
    def create(self, request, *args, **kwargs):
        input_data = request.data
        target_id = input_data.get('target')  # Get target ID
        scan_config_option = input_data.get('scan_config', 'FULL_AND_FAST')
        scanner_input = input_data.get('scanner', 'OPENVAS').upper() 

        # Map scanner options to UUIDs
        scanner_uuid_mapping = {
            'CVE': Scanner.CVE,
            'OPENVAS': Scanner.OPENVAS,
            'NIKTO': Scanner.NIKTO,
        }

        scanner_uuid = scanner_uuid_mapping.get(scanner_input, Scanner.OPENVAS)

        # Map scan configuration options to UUIDs
        scan_config_uuid_mapping = {
            'BASE': ScanConfig.BASE,
            'DISCOVERY': ScanConfig.DISCOVERY,
            'EMPTY': ScanConfig.EMPTY,
            'FULL_AND_FAST': ScanConfig.FULL_AND_FAST,
            'HOST_DISCOVERY': ScanConfig.HOST_DISCOVERY,
            'LOG4SHELL': ScanConfig.LOG4SHELL,
            'SYSTEM_DISCOVERY': ScanConfig.SYSTEM_DISCOVERY,
        }

        scan_config = scan_config_uuid_mapping.get(scan_config_option, ScanConfig.FULL_AND_FAST)

        # Create a task name
        task_name = f"{target_id}-{scan_config}"
        
        data = {
            'target': target_id,
            'scan_config': scan_config,
            'task_name': task_name,
            'scanner': scanner_uuid
        }

        try:
            # Create task in OpenVAS
            task_id = create_task(target_id, scan_config, task_name, scanner_uuid)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        data['task_id'] = task_id

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)  # Save to DB
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    # Start an OpenVAS task
    @action(detail=True, methods=['post'])
    def start_task(self, request, pk=None):
        task = self.get_object() 
        try:
            start_task(task.task_id)  # Start task
            wait_for_task_completion.delay(task.task_id)  # Monitor task completion
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'status': "Started"}, status=status.HTTP_200_OK)

    # Create and start a scan task at the same time
    @action(detail=False, methods=['post'])
    def create_and_start_task(self, request):
        input_data = request.data
        value = input_data.get('value')
        port_list_option = input_data.get('port_list', PortList.IANA_ASSIGNED_TCP)
        scan_config_option = input_data.get('scan_config', 'FULL_AND_FAST')
        scanner_input = input_data.get('scanner', 'OPENVAS').upper()

        # Map port list option to UUID
        port_list_uuid_mapping = {
            'IANA_ASSIGNED_TCP': PortList.IANA_ASSIGNED_TCP,
            'ALL_IANA_ASSIGNED_TCP_UDP': PortList.ALL_IANA_ASSIGNED_TCP_UDP,
            'ALL_TCP_NMAP_TOP_100_UDP': PortList.ALL_TCP_NMAP_TOP_100_UDP,
        }
        port_list = port_list_uuid_mapping.get(port_list_option, PortList.IANA_ASSIGNED_TCP)

        # Map scanner input to UUID
        scanner_uuid_mapping = {
            'CVE': Scanner.CVE,
            'OPENVAS': Scanner.OPENVAS,
            'NIKTO': Scanner.NIKTO,
        }
        scanner_uuid = scanner_uuid_mapping.get(scanner_input, Scanner.OPENVAS)

        # Map scan configuration input to UUID
        scan_config_uuid_mapping = {
            'BASE': ScanConfig.BASE,
            'DISCOVERY': ScanConfig.DISCOVERY,
            'EMPTY': ScanConfig.EMPTY,
            'FULL_AND_FAST': ScanConfig.FULL_AND_FAST,
            'HOST_DISCOVERY': ScanConfig.HOST_DISCOVERY,
            'LOG4SHELL': ScanConfig.LOG4SHELL,
            'SYSTEM_DISCOVERY': ScanConfig.SYSTEM_DISCOVERY,
        }
        scan_config = scan_config_uuid_mapping.get(scan_config_option, ScanConfig.FULL_AND_FAST)

        # Validate input value type
        value_type = validate_input(value)
        
        if value_type not in ["domain_name", "ip_address", "hostname"]:
            return Response({'error': 'This target cannot be scanned by OpenVAS'}, status=status.HTTP_400_BAD_REQUEST)

        target_name = value + '-' + port_list
        target = Target.objects.filter(value=value, port_list=port_list).first()

        # Create a new target if it doesn't exist
        if not target:
            try:
                target_id = create_target(target_name, value, port_list)
                target_data = {
                    'value': value,
                    'port_list': port_list,
                    'target_name': target_name,
                    'target_id': target_id,
                    'value_type': value_type,
                }
                target_serializer = TargetSerializer(data=target_data)
                target_serializer.is_valid(raise_exception=True)
                target = target_serializer.save()
            except Exception as e:
                return Response({'error': f'Error creating target: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        task_name = f"{target.target_id}-{scan_config}"
        task = Task.objects.filter(target=target, scan_config=scan_config).first()

        # Create a new task if it doesn't exist
        if not task:
            try:
                task_id = create_task(target.target_id, scan_config, task_name, scanner_uuid)
                task_data = {
                    'target': target.target_id,
                    'scan_config': scan_config,
                    'task_name': task_name,
                    'scanner': scanner_uuid,
                    'task_id': task_id
                }
                task_serializer = TaskSerializer(data=task_data)
                task_serializer.is_valid(raise_exception=True)
                task = task_serializer.save()
            except Exception as e:
                return Response({'error': f'Error creating task: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        scan_history = ScanHistory.objects.filter(task=task).order_by('-start_time').first()
        if scan_history and scan_history.status == 'Running':
            return Response({'status': "An existing scan is already running for this target."}, status=status.HTTP_400_BAD_REQUEST)
        # Start the created task
        try:
            start_task(task.task_id)
            wait_for_task_completion.delay(task.task_id)  # Monitor completion
        except Exception as e:
            return Response({'error': f'Error starting task: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': "Task created and started successfully"}, status=status.HTTP_200_OK)

    # Destroy method to delete a task
    def destroy(self, request, *args, **kwargs):
        task = self.get_object()
        try:
            delete_task(task.task_id)  # Delete task in OpenVAS
            task.delete() 
        except Exception as e:
            return Response({'error': f"Failed to delete task: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'status': 'Task deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

# VulnerabilityViewSet manages vulnerabilities found during scans
class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilitySerializer
    queryset = Vulnerability.objects.all()

# SecurityAlertViewSet manages alerts generated during scans
class SecurityAlertViewSet(viewsets.ModelViewSet):
    serializer_class = SecurityAlertSerializer
    queryset = SecurityAlert.objects.all()

# CrawlerViewSet manages the SpiderFoot crawlers
class CrawlerViewSet(viewsets.ModelViewSet):
    queryset = Crawler.objects.all()
    serializer_class = CrawlerSerializer

    # Custom create method for creating a new crawler
    def create(self, request, *args, **kwargs):
        target_value = request.data.get('value')
        if not target_value:
            return Response({"error": "Target is required."}, status=status.HTTP_400_BAD_REQUEST)

        validation_result = validate_input(target_value)
        if validation_result == "Invalid input":
            return Response({"error": "Invalid input"}, status=status.HTTP_400_BAD_REQUEST)

        target = Target.objects.filter(value=target_value).first()

        # Create a new target if it doesn't exist
        if not target:
            port_list = PortList.IANA_ASSIGNED_TCP
            target_name = target_value + '-' + port_list
            try:
                target_id = create_target(target_name, target_value, port_list)
                target_data = {
                    'value': target_value,
                    'port_list': port_list,
                    'target_name': target_name,
                    'target_id': target_id,
                    'value_type': validation_result,
                }
                target_serializer = TargetSerializer(data=target_data)
                target_serializer.is_valid(raise_exception=True)
                target = target_serializer.save()
            except Exception as e:
                return Response({'error': f'Error creating target: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        existing_crawler = Crawler.objects.filter(target=target.target_id).order_by('-start_time').first()
        if existing_crawler and existing_crawler.status == 'Running':
            return Response({'status': "An existing crawler is already running for this target."}, status=status.HTTP_400_BAD_REQUEST)
        # Prepare data for crawler creation
        post_data = {
            "scanname": target_value,
            "scantarget": target_value,
            "modulelist": "",
            "typelist": "",
            "usecase": "all"
        }

        try:
            scan_id = create_crawler(post=post_data)
        except Exception as e:
            return Response({"error": f"Failed to create scan: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        crawler_data = {
            'target': target.target_id,
            'start_time': now(),
            'status': 'Running',
            'crawler_id': scan_id,
        }

        serializer = self.get_serializer(data=crawler_data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        wait_for_crawler_complete.delay(scan_id)  # Monitor the completion

        return Response({'status': "Crawler created and started successfully"}, status=status.HTTP_200_OK)

# CorrelationsViewSet manages the correlations discovered from scans
class CorrelationsViewSet(viewsets.ModelViewSet):
    queryset = Correlation.objects.all()
    serializer_class = CorrelationSerializer

# TelegramUserViewSet manages Telegram users interacting with the system
class TelegramUserViewSet(viewsets.ModelViewSet):
    queryset = TelegramUser.objects.all()
    serializer_class = TelegramUserSerializer

    # Custom action to update a Telegram user's language preference
    @action(detail=True, methods=['post'])
    def update_lang(self, request, *args, **kwargs):
        telegram_id = kwargs.get('pk')
        language = request.data.get('language')

        instance, created = TelegramUser.objects.get_or_create(telegram_id=telegram_id)

        if not created:
            instance.language = language
            instance.save()

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK if not created else status.HTTP_201_CREATED)

# ScheduleTargetViewSet manages scheduling targets for periodic scans
class ScheduleTargetViewSet(viewsets.ModelViewSet):
    queryset = TargetSchedule.objects.all()
    serializer_class = TargetScheduleSerializer

    # Create a new target schedule
    def create(self, request, *args, **kwargs):
      
        target_value = request.data.get("value")
        scan_type = request.data.get("scan_type")  
        interval = request.data.get("interval")

        if not target_value or not scan_type or not interval:
            return Response({"error": "Missing value, scan_type, or interval."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            target = Target.objects.get(value=target_value)
            target_id = target.target_id
            value_type = target.value_type 
        except Target.DoesNotExist:

            backend_ip = os.getenv('BACKEND_IP')
            backend_port = os.getenv('BACKEND_PORT', '8000')
            targets_url = f"http://{backend_ip}:{backend_port}/targets/"

            target_payload = {
                "value": target_value,
            }

            try:
                response = requests.post(targets_url, json=target_payload)
                response.raise_for_status()
                target_data = response.json()
                target_id = target_data.get('target_id')
                value_type = target_data.get('value_type') 
                if not target_id or not value_type:
                    return Response({"error": "Failed to create target or retrieve value_type."},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except requests.RequestException as e:
                return Response({"error": f"Failed to create target via API: {str(e)}"},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if scan_type == 'openvas':
            if value_type not in ["domain_name", "ip_address", "hostname"]:
                return Response({"error": "Value is not valid for OpenVAS."}, status=status.HTTP_400_BAD_REQUEST)
        elif scan_type == 'spiderfoot':
            if value_type == "Invalid input":
                return Response({"error": "Value is not valid for SpiderFoot."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "Invalid scan type."}, status=status.HTTP_400_BAD_REQUEST)

        target_schedule, created = TargetSchedule.objects.update_or_create(
            target=target,
            defaults={"value": target_value, "interval": interval, "scan_type": scan_type, "last_run": None}
        )

        return Response({"message": f"Target '{target_value}' has been scheduled with scan_type '{scan_type}' every {interval} seconds."},
                        status=status.HTTP_201_CREATED)
    
# ScanHistoryViewSet manages the scan history of targets
class ScanHistoryViewSet(viewsets.ModelViewSet):
    queryset = ScanHistory.objects.all()
    serializer_class = ScanHistorySerializer
