import threading
import time
from scapy.all import sniff, TCP, IP
from django.utils import timezone
from .detectors import detect, DetectionState, get_config
from .models import PacketLog, SecurityAlert, MonitoringSession


class SnifferService:
    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.state = None
        self.session = None
        self.interface = None

    def start(self, interface: str):
        if self.thread and self.thread.is_alive():
            return
        self.interface = interface
        self.stop_event.clear()
        self.state = DetectionState(get_config())
        self.session = MonitoringSession.objects.create(interface=interface)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.session:
            self.session.is_active = False
            self.session.ended_at = timezone.now()
            self.session.save()

    def _handle_packet(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]
        flags = tcp.flags.flagrepr()
        record = {
            "ts": time.time(),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": flags,
            "seq": int(tcp.seq),
            "ack": int(tcp.ack),
            "length": len(pkt),
        }
        PacketLog.objects.create(
            src_ip=record["src_ip"],
            dst_ip=record["dst_ip"],
            src_port=record["src_port"],
            dst_port=record["dst_port"],
            flags=record["flags"],
            seq=record["seq"],
            ack=record["ack"],
            length=record["length"],
            timestamp=timezone.now(),
        )
        alerts = detect(record, self.state)
        for alert in alerts:
            SecurityAlert.objects.create(
                alert_type=alert["type"],
                severity=alert["severity"],
                src_ip=alert["src_ip"],
                dst_ip=alert["dst_ip"],
                description=alert["description"],
                evidence=alert["evidence"],
                dedup_key=alert["dedup_key"],
            )

    def _run(self):
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            stop_filter=lambda _: self.stop_event.is_set(),
            store=False,
        )
