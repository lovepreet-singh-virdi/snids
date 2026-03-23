from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("alerts/", views.alerts, name="alerts"),
    path("alerts/<int:pk>/", views.alert_detail, name="alert_detail"),
    path("traffic/", views.traffic, name="traffic"),
    path("monitoring/", views.monitoring, name="monitoring"),
    path("settings/", views.settings_view, name="settings"),
    path("api/start/", views.start_sniff, name="start_sniff"),
    path("api/stop/", views.stop_sniff, name="stop_sniff"),
    path("api/status/", views.status, name="status"),
    path("api/interfaces/", views.interfaces, name="interfaces"),
]
