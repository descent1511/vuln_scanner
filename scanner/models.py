from django.db import models

# Define port list options using Django's TextChoices
class PortList(models.TextChoices):
    IANA_ASSIGNED_TCP = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'  # Default TCP ports
    ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'  # All TCP/UDP ports
    ALL_TCP_NMAP_TOP_100_UDP = '730ef368-57e2-11e1-a90f-406186ea4fc5'  # Top 100 UDP ports

# Define scan configurations using Django's TextChoices
class ScanConfig(models.TextChoices):
    BASE = 'd21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663'
    DISCOVERY = '8715c877-47a0-438d-98a3-27c7a6ab2196'
    EMPTY = '085569ce-73ed-11df-83c3-002264764cea'
    FULL_AND_FAST = 'daba56c8-73ec-11df-a475-002264764cea'  # Default scanning mode
    HOST_DISCOVERY = '2d3f051c-55ba-11e3-bf43-406186ea4fc5'
    LOG4SHELL = 'e3efebc5-fc0d-4cb6-b1b4-55309d0a89f6'
    SYSTEM_DISCOVERY = 'bbca7412-a950-11e3-9109-406186ea4fc5'

# Define scanners using Django's TextChoices
class Scanner(models.TextChoices):
    CVE = '6acd0832-df90-11e4-b9d5-28d24461215b'  # CVE-based scanner
    OPENVAS = '08b69003-5fc2-4037-a479-93b440211c73'  # OpenVAS scanner
    NIKTO = ''  # Placeholder for Nikto scanner

# Define a model representing scanning targets
class Target(models.Model):
    target_name = models.CharField(max_length=255, blank=True)  # Target name
    value = models.CharField(max_length=255)  # IP/domain value
    port_list = models.CharField(
        max_length=40,
        choices=PortList.choices,  # Choose from PortList options
        default=PortList.IANA_ASSIGNED_TCP  # Default choice
    )
    target_id = models.CharField(max_length=40, primary_key=True, blank=True)  # Unique target ID
    value_type = models.CharField(max_length=40)  # Type of value (IP/domain/hostname)

# Define a model for scheduling periodic scans
class TargetSchedule(models.Model):
    SCAN_TYPE_CHOICES = [
        ('openvas', 'OpenVAS'),
        ('spiderfoot', 'SpiderFoot'),
    ]
    target = models.ForeignKey(Target, on_delete=models.CASCADE)  # Link to Target model
    value = models.CharField(max_length=255)  # Value to be scanned
    interval = models.IntegerField()  # Interval in seconds
    last_run = models.DateTimeField(null=True, blank=True)  # Last run time
    scan_type = models.CharField(max_length=40, choices=SCAN_TYPE_CHOICES)  # Choose scan type

    def __str__(self):
        return f"{self.value} ({self.scan_type})"

# Define a model for scan tasks
class Task(models.Model):
    task_name = models.CharField(max_length=255, blank=True)  # Task name
    target = models.ForeignKey(Target, on_delete=models.CASCADE)  # Link to Target model
    scan_config = models.CharField(
        max_length=40,
        choices=ScanConfig.choices,
        default=ScanConfig.FULL_AND_FAST
    )
    task_id = models.CharField(max_length=40, primary_key=True, blank=True)  # Unique task ID
    scanner = models.CharField(
        max_length=40,
        choices=Scanner.choices,
        default=Scanner.CVE
    )

# Define a model to store scan history details
class ScanHistory(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='scans')  # Link to Task model
    start_time = models.DateTimeField(auto_now_add=True)  # Auto set start time
    end_time = models.DateTimeField(null=True, blank=True)  # End time

    hosts = models.JSONField(default=list, blank=True)  # List of hosts
    ports = models.JSONField(default=list, blank=True)  # List of ports
    vulnerabilities = models.JSONField(default=list, blank=True)  # List of vulnerabilities
    applications = models.JSONField(default=list, blank=True)  # List of applications found
    operating_system = models.CharField(max_length=100, blank=True)  # OS of the scanned target
    cve_names = models.JSONField(default=list, blank=True)  # List of CVE names
    scan_id = models.CharField(max_length=40, primary_key=True, blank=True)  # Unique scan ID

    def __str__(self):
        return f"Scan {self.id} for Task {self.task.task_name}"

# Define a model for vulnerabilities
class Vulnerability(models.Model):
    name = models.CharField(max_length=255)  # Vulnerability name
    description = models.TextField()  # Detailed description
    severity = models.CharField(max_length=50)  # Severity level
    references = models.TextField(blank=True, null=True)  # External references
    published_date = models.DateField()  # Date of publication
    affected_versions = models.TextField()  # Affected versions
    solution = models.TextField()  # Solution to the vulnerability
    title = models.CharField(max_length=255)  # Title of the vulnerability
    created_at = models.DateTimeField(auto_now_add=True)  # Auto set creation time
    updated_at = models.DateTimeField(auto_now=True)  # Auto update on changes

    def __str__(self):
        return self.name

# Define a model for security alerts
class SecurityAlert(models.Model):
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(auto_now_add=True)  # Auto set timestamp
    severity = models.CharField(max_length=10)  # Alert severity
    name = models.CharField(max_length=255)  # Alert name
    ip_address = models.GenericIPAddressField()  # IP address of the target
    hostname = models.CharField(max_length=255, null=True, blank=True)  # Hostname
    port = models.CharField(max_length=40, null=True, blank=True)  # Port involved
    service = models.CharField(max_length=100, default='All')  # Service type
    recommendation = models.TextField()  # Recommended actions
    status = models.CharField(max_length=20, default='Unresolved')  # Alert status
    notified = models.BooleanField(default=False)  # Notification status
    notification_sent_at = models.DateTimeField(null=True, blank=True)  # Time of notification
    notification_channel = models.CharField(max_length=50, default='Telegram')  # Notification channel
    owner = models.CharField(max_length=100, default='Viettel Cloud Security Team')  # Owner of the alert
    original_threat = models.CharField(max_length=50, null=True, blank=True)  # Original threat type
    original_severity = models.CharField(max_length=50, null=True, blank=True)  # Original severity
    modification_time = models.DateTimeField(null=True, blank=True)  # Last modification time
    creation_time = models.DateTimeField(null=True, blank=True)  # Creation time
    nvt_oid = models.CharField(max_length=255, null=True, blank=True)  # OID of the NVT
    cvss_base_score = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)  # CVSS base score
    severity_score = models.DecimalField(max_digits=4, decimal_places=2, null=True, blank=True)  # Severity score
    severity_origin = models.CharField(max_length=255, null=True, blank=True)  # Origin of severity
    description = models.TextField(null=True, blank=True)  # Description of the alert
    solution = models.TextField(null=True, blank=True)  # Solution to the alert
    references = models.TextField(null=True, blank=True)  # External references

    def __str__(self):
        return f"Alert {self.id} - {self.name} - {self.ip_address}"

# Define a model for managing data crawlers
class Crawler(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)  # Link to Target model
    start_time = models.DateTimeField(auto_now_add=True)  # Start time of the crawl
    end_time = models.DateTimeField(null=True, blank=True)  # End time of the crawl
    num_threats_collected = models.IntegerField(default=0)  # Number of threats collected
    crawler_id = models.CharField(max_length=36, primary_key=True, blank=True)  # Unique ID
    status = models.CharField(max_length=50)  # Current status of the crawl

# Define a model for correlations between data crawls
class Correlation(models.Model):
    crawler = models.ForeignKey(Crawler, related_name='correlations', on_delete=models.CASCADE)  # Link to Crawler
    correlation_id = models.CharField(max_length=36, primary_key=True)  # Unique correlation ID
    headline = models.TextField()  # Correlation headline
    collection_type = models.CharField(max_length=100)  # Type of data collected
    risk_level = models.CharField(max_length=10)  # Risk level of the correlation
    description = models.TextField()  # Detailed description
    detailed_info = models.TextField()  # Detailed information
    metadata = models.TextField()  # Metadata associated
    occurrences = models.IntegerField()  # Number of occurrences

    def __str__(self):
        return f"{self.headline} ({self.collection_type})"

# Define a model for Telegram users
class TelegramUser(models.Model):
    telegram_id = models.CharField(primary_key=True, max_length=50)  # Unique Telegram user ID
    language = models.CharField(max_length=10, default='en')  # User's preferred language

    def __str__(self):
        return f"User {self.telegram_id} ({self.language})"

    # Method to set a new language for the user
    def set_language(self, new_language):
        supported_languages = ['en', 'vi']  # Supported languages
        if new_language in supported_languages:
            self.language = new_language
            self.save()  # Save the change
            return True
        return False
