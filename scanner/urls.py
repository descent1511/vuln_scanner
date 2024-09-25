from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .telegram_bot import TelegramBot  # Import the Telegram bot class
from .views import (
    TargetViewSet,
    TaskViewSet,
    VulnerabilityViewSet,
    SecurityAlertViewSet,
    CrawlerViewSet,
    CorrelationsViewSet,
    TelegramUserViewSet,
    ScheduleTargetViewSet,
    ScanHistoryViewSet
)
from .views import threat_intelligence_view

# Initialize the Telegram bot instance (commented out here)
# bot = TelegramBot()
# bot.bot.polling()  # Start polling to handle incoming messages

# Create a DefaultRouter instance
router = DefaultRouter()
# Register viewsets with the router
router.register(r'targets', TargetViewSet)  # Register the TargetViewSet with the URL prefix 'targets'
router.register(r'tasks', TaskViewSet)  # Register the TaskViewSet with the URL prefix 'tasks'
router.register(r'vulnerabilities', VulnerabilityViewSet)  # Register the VulnerabilityViewSet with the URL prefix 'vulnerabilities'
router.register(r'security-alerts', SecurityAlertViewSet)  # Register the SecurityAlertViewSet with the URL prefix 'security-alerts'
router.register(r'crawlers', CrawlerViewSet)  # Register the CrawlerViewSet with the URL prefix 'crawlers'
router.register(r'correlations', CorrelationsViewSet)  # Register the CorrelationsViewSet with the URL prefix 'correlations'
router.register(r'users', TelegramUserViewSet)  # Register the TelegramUserViewSet with the URL prefix 'users'
router.register(r'schedules', ScheduleTargetViewSet)  # Register the ScheduleTargetViewSet with the URL prefix 'schedules'
router.register(r'scan-history', ScanHistoryViewSet)  # Register the ScanHistoryViewSet with the URL prefix 'scan-history'

# Define URL patterns
urlpatterns = [
    path('threat-intelligence/', threat_intelligence_view, name='threat_intelligence'),  # URL path for the threat intelligence view
    # Additional URL paths (commented out as they are not active currently)
    # path('routes/<int:route_id>/drivers/', DriversOnRouteView.as_view(), name='drivers-on-route'),
    # path('routes/search/', BusScheduleView.as_view(), name='bus-schedule'),
    # path('breakdowns/<str:date>/inactive-buses/', InactiveBusesView.as_view(), name='inactive-buses'),
    # path('drivers/class/<str:class_name>/', DriverCountByClassView.as_view(), name='driver-count-by-class'),
]

# Append the automatically generated URLs from the registered router to the urlpatterns list
urlpatterns += router.urls
