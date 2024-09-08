from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .telegram_bot import TelegramBot
from .views import (
    TargetViewSet,
    TaskViewSet,
    VulnerabilityViewSet,
    SecurityAlertViewSet,
    CrawlerViewSet,
    CorrelationsViewSet,
    TelegramUserViewSet
)

# bot = TelegramBot()
# bot.bot.polling()
router = DefaultRouter()
router.register(r'targets', TargetViewSet)
router.register(r'tasks', TaskViewSet)
router.register(r'vulnerabilities', VulnerabilityViewSet)
router.register(r'security-alerts', SecurityAlertViewSet)
router.register(r'crawlers', CrawlerViewSet)
router.register(r'correlations', CorrelationsViewSet)
router.register(r'users', TelegramUserViewSet)
urlpatterns = [
    # path('routes/<int:route_id>/drivers/', DriversOnRouteView.as_view(), name='drivers-on-route'),
    # path('routes/search/', BusScheduleView.as_view(), name='bus-schedule'),
    # path('breakdowns/<str:date>/inactive-buses/', InactiveBusesView.as_view(), name='inactive-buses'),
    # path('drivers/class/<str:class_name>/', DriverCountByClassView.as_view(), name='driver-count-by-class'),
]

urlpatterns += router.urls
