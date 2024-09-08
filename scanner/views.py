import time
from .serializers import TargetSerializer, TaskSerializer, VulnerabilitySerializer, SecurityAlertSerializer,CrawlerSerializer,CorrelationSerializer, TelegramUserSerializer
from .models import Target,PortList, Task,ScanConfig, Scanner, Vulnerability, SecurityAlert, Crawler,Correlation, TelegramUser
from rest_framework import generics, viewsets, status
from django.utils.timezone import now
import xml.etree.ElementTree as ET 
from .services.gvm import create_target, create_task,start_task, get_report_id,get_report_content,get_task_status
from rest_framework.response import Response
from rest_framework import viewsets
import requests
from rest_framework.decorators import action
from .tasks import wait_for_task_completion,run_spiderfoot_scan_task

class TargetViewSet(viewsets.ModelViewSet):
    queryset = Target.objects.all()
    serializer_class = TargetSerializer  

    def create(self, request, *args, **kwargs):
        input_data = request.data
        hosts = input_data.get('hosts')
        
        port_list_option = input_data.get('port_list', PortList.IANA_ASSIGNED_TCP)

        port_list_uuid_mapping = {
            'IANA_ASSIGNED_TCP': PortList.IANA_ASSIGNED_TCP,
            'ALL_IANA_ASSIGNED_TCP_UDP': PortList.ALL_IANA_ASSIGNED_TCP_UDP,
            'ALL_TCP_NMAP_TOP_100_UDP': PortList.ALL_TCP_NMAP_TOP_100_UDP,
        }

        port_list = port_list_uuid_mapping.get(port_list_option, PortList.IANA_ASSIGNED_TCP)

        target_name = hosts + '-' + port_list

        data = {
            'hosts': hosts,
            'port_list': port_list,
            'target_name': target_name
        }
        try:
            target_id = create_target(target_name, hosts, port_list)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        data['target_id'] = target_id
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
class TaskViewSet(viewsets.ModelViewSet):
    serializer_class = TaskSerializer
    queryset = Task.objects.all()
    # permission_classes = [IsAdminUser]

    def create(self, request, *args, **kwargs):
        input_data = request.data
        target_id = input_data.get('target')
        scan_config_option = input_data.get('scan_config', 'FULL_AND_FAST')
        scanner_input = input_data.get('scanner', 'OPENVAS').upper() 

        scanner_uuid_mapping = {
            'CVE': Scanner.CVE,
            'OPENVAS': Scanner.OPENVAS,
            'NIKTO': Scanner.NIKTO,
        }

        scanner_uuid = scanner_uuid_mapping.get(scanner_input, Scanner.OPENVAS)

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

        task_name = f"{target_id}-{scan_config}"

        data = {
            'target': target_id,
            'scan_config': scan_config,
            'task_name': task_name,
            'scanner': scanner_uuid
        }

        try:
            task_id = create_task(target_id, scan_config, task_name, scanner_uuid)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        data['task_id'] = task_id

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


    @action(detail=True, methods=['post'])
    def start_task(self, request, pk=None):
        task = self.get_object() 
        try:
            # start_task(task.task_id)  
            wait_for_task_completion.delay(task.task_id)
          
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'status': "Started"},status=status.HTTP_200_OK)


    @action(detail=False, methods=['post'])
    def create_and_start_task(self, request):
        input_data = request.data
        hosts = input_data.get('hosts')
        port_list_option = input_data.get('port_list', PortList.IANA_ASSIGNED_TCP)
        scan_config_option = input_data.get('scan_config', 'FULL_AND_FAST')
        scanner_input = input_data.get('scanner', 'OPENVAS').upper()

        port_list_uuid_mapping = {
            'IANA_ASSIGNED_TCP': PortList.IANA_ASSIGNED_TCP,
            'ALL_IANA_ASSIGNED_TCP_UDP': PortList.ALL_IANA_ASSIGNED_TCP_UDP,
            'ALL_TCP_NMAP_TOP_100_UDP': PortList.ALL_TCP_NMAP_TOP_100_UDP,
        }
        port_list = port_list_uuid_mapping.get(port_list_option, PortList.IANA_ASSIGNED_TCP)

        scanner_uuid_mapping = {
            'CVE': Scanner.CVE,
            'OPENVAS': Scanner.OPENVAS,
            'NIKTO': Scanner.NIKTO,
        }
        scanner_uuid = scanner_uuid_mapping.get(scanner_input, Scanner.OPENVAS)

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

        target_name = hosts + '-' + port_list
        target = Target.objects.filter(hosts=hosts, port_list=port_list).first()

        if not target:
            try:
                target_id = create_target(target_name, hosts, port_list)
                target_data = {
                    'hosts': hosts,
                    'port_list': port_list,
                    'target_name': target_name,
                    'target_id': target_id
                }
                target_serializer = TargetSerializer(data=target_data)
                target_serializer.is_valid(raise_exception=True)
                target = target_serializer.save()
            except Exception as e:
                return Response({'error': f'Error creating target: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        task_name = f"{target.target_id}-{scan_config}"
        task = Task.objects.filter(target=target, scan_config=scan_config).first()

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
                # print(task_data)
                task_serializer = TaskSerializer(data=task_data)
                task_serializer.is_valid(raise_exception=True)
                task = task_serializer.save()
            except Exception as e:
                return Response({'error': f'Error creating task: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_task(task.task_id)
            wait_for_task_completion.delay(task.task_id)
        except Exception as e:
            return Response({'error': f'Error starting task: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': "Task created and started successfully"}, status=status.HTTP_200_OK)
    


class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilitySerializer
    queryset = Vulnerability.objects.all()

class SecurityAlertViewSet(viewsets.ModelViewSet):
    serializer_class = SecurityAlertSerializer
    queryset = SecurityAlert.objects.all()

class CrawlerViewSet(viewsets.ModelViewSet):
    queryset = Crawler.objects.all()
    serializer_class = CrawlerSerializer

    def create(self, request, *args, **kwargs):
    
        target_id = request.data.get('target_id')

        try:
            target = Target.objects.get(target_id=target_id)
        except Target.DoesNotExist:
            return Response({"error": "Target not found."}, status=status.HTTP_404_NOT_FOUND)

        ip_address = target.hosts
        run_spiderfoot_scan_task.delay(ip_address)
        time.sleep(2)
        try:
            response = requests.get("http://192.168.102.133:5001/scanlist")
            response.raise_for_status()
            scan_list = response.json()

            if not scan_list or not isinstance(scan_list, list):
                return Response({"error": "Invalid scan list returned from API."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            scan_id = scan_list[0][0]
            crawler_data = {
                'target': target_id,  
                'start_time': now(),
                'status': 'Running',
                'crawler_id': scan_id,
            }

            # Create and save the Crawler instance
            serializer = self.get_serializer(data=crawler_data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        except requests.RequestException as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class CorrelationsViewSet(viewsets.ModelViewSet):
    queryset = Correlation.objects.all()
    serializer_class = CorrelationSerializer

class TelegramUserViewSet(viewsets.ModelViewSet):
    queryset = TelegramUser.objects.all()
    serializer_class = TelegramUserSerializer

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