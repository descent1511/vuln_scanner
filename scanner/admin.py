from django.contrib import admin
from .models import Target,Task, Crawler, TelegramUser, SecurityAlert
admin.site.register(Target)
admin.site.register(Task)
admin.site.register(Crawler)
admin.site.register(TelegramUser)
admin.site.register(SecurityAlert)