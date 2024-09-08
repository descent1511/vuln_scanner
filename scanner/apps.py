from django.apps import AppConfig
from django.conf import settings
from .services.gvm import ssh_connect

ssh_client = None

class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'
    def ready(self):
        ssh_client, error = ssh_connect()
        if ssh_client:
            print("SSH connection established")
        else:
            print(f"SSH connection failed: {error}")

       