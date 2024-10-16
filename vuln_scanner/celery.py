from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')

app = Celery('vuln_scanner')  # Replace 'your_project' with your project's name.

# Configure Celery using settings from Django settings.py.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.conf.beat_scheduler = 'django_celery_beat.schedulers.DatabaseScheduler'
# Load tasks from all registered Django app configs.
app.autodiscover_tasks(lambda: ['scanner.tasks.openvas_task','scanner.tasks.spiderfoot_task','scanner.tasks.schedule_task'])