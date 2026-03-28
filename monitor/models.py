from django.db import models
from django.utils import timezone

SEVERITY_CHOICES = [
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]


class NetworkInterfaceConfig(models.Model):
    name = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=128, blank=True)
    active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({'active' if self.active else 'inactive'})"


class MonitoringSession(models.Model):
    interface = models.CharField(max_length=64)
    started_at = models.DateTimeField(default=timezone.now)
    ended_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    mode = models.CharField(max_length=16, default="live", choices=[("live", "Live"), ("pcap", "PCAP")])
    pcap_name = models.CharField(max_length=255, blank=True, null=True)
    packet_count = models.BigIntegerField(default=0)
    alert_count = models.BigIntegerField(default=0)
    processing_ms_total = models.BigIntegerField(default=0)


class DetectionSetting(models.Model):
    syn_threshold = models.IntegerField(default=50)
    syn_window_seconds = models.IntegerField(default=10)
    handshake_completion_min_ratio = models.FloatField(default=0.2)
    rst_threshold = models.IntegerField(default=20)
    rst_window_seconds = models.IntegerField(default=10)
    hijack_seq_jump = models.IntegerField(default=500000)
    alert_cooldown_seconds = models.IntegerField(default=30)
    updated_at = models.DateTimeField(auto_now=True)


class PacketLog(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    flags = models.CharField(max_length=16)
    seq = models.BigIntegerField(null=True, blank=True)
    ack = models.BigIntegerField(null=True, blank=True)
    length = models.IntegerField()
    protocol = models.CharField(max_length=8, default="TCP")


class ConnectionStat(models.Model):
    flow_id = models.CharField(max_length=128, unique=True)  # src:port-dst:port
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_port = models.IntegerField()
    syn_count = models.IntegerField(default=0)
    synack_count = models.IntegerField(default=0)
    ack_count = models.IntegerField(default=0)
    rst_count = models.IntegerField(default=0)
    last_seen = models.DateTimeField(default=timezone.now)


class SecurityAlert(models.Model):
    created_at = models.DateTimeField(default=timezone.now)
    alert_type = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField()
    evidence = models.JSONField(default=dict)
    dedup_key = models.CharField(max_length=128, db_index=True)

    class Meta:
        ordering = ["-created_at"]
