from django.contrib import admin
from .models import (
    NetworkInterfaceConfig,
    MonitoringSession,
    DetectionSetting,
    PacketLog,
    ConnectionStat,
    SecurityAlert,
)

admin.site.register(NetworkInterfaceConfig)
admin.site.register(MonitoringSession)
admin.site.register(DetectionSetting)
admin.site.register(PacketLog)
admin.site.register(ConnectionStat)
admin.site.register(SecurityAlert)
