from django.db import models

class PortList(models.TextChoices):
    IANA_ASSIGNED_TCP = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
    ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
    ALL_TCP_NMAP_TOP_100_UDP = '730ef368-57e2-11e1-a90f-406186ea4fc5'

class ScanConfig(models.TextChoices):
    BASE = 'd21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663'
    DISCOVERY = '8715c877-47a0-438d-98a3-27c7a6ab2196'
    EMPTY = '085569ce-73ed-11df-83c3-002264764cea'
    FULL_AND_FAST = 'daba56c8-73ec-11df-a475-002264764cea'
    HOST_DISCOVERY = '2d3f051c-55ba-11e3-bf43-406186ea4fc5'
    LOG4SHELL = 'e3efebc5-fc0d-4cb6-b1b4-55309d0a89f6'
    SYSTEM_DISCOVERY = 'bbca7412-a950-11e3-9109-406186ea4fc5'

class Scanner(models.TextChoices):
    CVE = '6acd0832-df90-11e4-b9d5-28d24461215b'
    OPENVAS = '08b69003-5fc2-4037-a479-93b440211c73'
    NIKTO = ''


class Target(models.Model):
    target_name = models.CharField(max_length=255, blank=True)
    value = models.CharField(max_length=255)
    port_list = models.CharField(
        max_length=40,
        choices=PortList.choices,
        default=PortList.IANA_ASSIGNED_TCP
    )
    target_id = models.CharField(max_length=40, primary_key=True, blank=True)
    value_type = models.CharField(max_length=40)

class TargetSchedule(models.Model):
    SCAN_TYPE_CHOICES = [
        ('openvas', 'OpenVAS'),
        ('spiderfoot', 'SpiderFoot'),
    ]
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    value = models.CharField(max_length=255)
    interval = models.IntegerField()
    last_run = models.DateTimeField(null=True, blank=True)
    scan_type = models.CharField(max_length=40, choices=SCAN_TYPE_CHOICES)

    def __str__(self):
        return f"{self.value} ({self.scan_type})"

    
class Task(models.Model):
    task_name = models.CharField(max_length=255, blank=True)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    scan_config = models.CharField(
        max_length=40,
        choices=ScanConfig.choices,
        default=ScanConfig.FULL_AND_FAST
    )
    task_id = models.CharField(max_length=40, primary_key=True, blank=True)
    scanner = models.CharField(
        max_length=40,
        choices=Scanner.choices,
        default=Scanner.CVE
    )

class ScanHistory(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='scans')
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)

    hosts = models.JSONField(default=list, blank=True)
    ports = models.JSONField(default=list, blank=True)
    vulnerabilities = models.JSONField(default=list, blank=True)       
    applications = models.JSONField(default=list, blank=True)   
    operating_system = models.CharField(max_length=100, blank=True) 
    cve_names = models.JSONField(default=list, blank=True)    
    scan_id = models.CharField(max_length=40, primary_key=True, blank=True)
    def __str__(self):
        return f"Scan {self.id} for Task {self.task.task_name}"


class Vulnerability(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=50)
    references = models.TextField(blank=True, null=True)
    published_date = models.DateField()
    affected_versions = models.TextField()
    solution = models.TextField()
    title = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.name
    

class SecurityAlert(models.Model):
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=10)
    name = models.CharField(max_length=255) 
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, null=True, blank=True)  
    port = models.CharField(max_length=40,null=True, blank=True)
    service = models.CharField(max_length=100, default='All')
    recommendation = models.TextField()
    status = models.CharField(max_length=20, default='Unresolved')
    notified = models.BooleanField(default=False)
    notification_sent_at = models.DateTimeField(null=True, blank=True)
    notification_channel = models.CharField(max_length=50, default='Telegram')
    owner = models.CharField(max_length=100, default='Viettel Cloud Security Team')
    original_threat = models.CharField(max_length=50, null=True, blank=True) 
    original_severity = models.CharField(max_length=50, null=True, blank=True) 
    modification_time = models.DateTimeField(null=True, blank=True) 
    creation_time = models.DateTimeField(null=True, blank=True)
    nvt_oid = models.CharField(max_length=255, null=True, blank=True) 
    cvss_base_score = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)  
    severity_score = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)  
    severity_origin = models.CharField(max_length=255, null=True, blank=True)  
    description = models.TextField(null=True, blank=True) 
    solution = models.TextField(null=True, blank=True) 
    references = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Alert {self.id} - {self.name} - {self.ip_address}"


class Crawler(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    num_threats_collected = models.IntegerField(default=0)
    crawler_id = models.CharField(max_length=36, primary_key=True, blank=True)
    status = models.CharField(max_length=50)
    
    
class Correlation(models.Model):
    crawler = models.ForeignKey(Crawler, related_name='correlations', on_delete=models.CASCADE)
    correlation_id = models.CharField(max_length=36, primary_key=True)
    headline = models.TextField()
    collection_type = models.CharField(max_length=100)
    risk_level = models.CharField(max_length=10)
    description = models.TextField()
    detailed_info = models.TextField()
    metadata = models.TextField()
    occurrences = models.IntegerField()

    def __str__(self):
        return f"{self.headline} ({self.collection_type})"

class TelegramUser(models.Model):
    telegram_id = models.CharField(primary_key=True,max_length=50)
    language = models.CharField(max_length=10, default='en') 

    def __str__(self):
        return f"User {self.telegram_id} ({self.language})"

    def set_language(self, new_language):
        supported_languages = ['en', 'vi'] 
        if new_language in supported_languages:
            self.language = new_language
            self.save() 
            return True
        return False 
