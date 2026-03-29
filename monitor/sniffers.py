import time
from pathlib import Path
from scapy.all import AsyncSniffer, TCP, IP, rdpcap
from django.utils import timezone
from .detectors import detect, DetectionState, get_config
from .models import PacketLog, SecurityAlert, MonitoringSession


class SnifferService:
    def __init__(self):
        self.sniffer = None
        self.state = None
        self.session = None
        self.interface = None
        self.mode = "live"

    def _normalize_interface(self, iface: str) -> str:
        """
        On Windows, Scapy needs the Npcap device name (\\Device\\NPF_*).
        Map common friendly names to their Npcap form.
        """
        try:
            import platform
            if platform.system() != "Windows":
                return iface

            # Strip trailing IP in parentheses, normalize unicode hyphens, collapse slashes.
            iface_clean = iface.split("(")[0].strip()
            iface_clean = iface_clean.replace("\u2011", "-").replace("\u2010", "-").replace("\u2013", "-").replace("\u2014", "-")
            iface_clean = iface_clean.replace("\\\\", "\\")

            # If caller passed an Npcap name, normalize slashes and use it.
            if iface_clean.startswith("\\Device\\NPF_") or iface_clean.startswith(r"\Device\NPF_"):
                return iface_clean.replace("\\\\", "\\")

            # Loopback special-case: map to known token
            if "loopback" in iface_clean.lower():
                return r"\Device\NPF_Loopback"

            # For other adapters, Scapy can resolve friendly names like "Wi-Fi" directly.
            # Prefer returning the cleaned friendly name to avoid bad GUID mapping.
            return iface_clean
        except Exception:
            # Fall back to the original interface if mapping fails.
            pass

        return iface_clean

    def is_running(self) -> bool:
        return bool(self.sniffer and getattr(self.sniffer, "running", False))

    def start(self, interface: str):
        if not interface:
            raise ValueError("Interface is required")
        if self.is_running():
            return
        self.interface = self._normalize_interface(interface)
        self.mode = "live"
        self.state = DetectionState(get_config())
        self.session = MonitoringSession.objects.create(interface=interface, mode="live")
        # AsyncSniffer lets us stop cleanly even when traffic is idle
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=lambda pkt: self._handle_packet(pkt, record_session=True),
            store=False,
        )
        self.sniffer.start()

    def stop(self):
        """
        Stop the sniffer; always try to close the session, even if sniffer.stop()
        raises (e.g., thread already dead).
        Returns an optional error string.
        """
        err = None
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as exc:  # best-effort stop
                err = str(exc)
            finally:
                self.sniffer = None
        if self.session:
            self.session.is_active = False
            self.session.ended_at = timezone.now()
            self.session.save(update_fields=["is_active", "ended_at"])
            self.session = None
        self.interface = None
        return err

    def process_pcap(self, pcap_path: Path):
        """Process a pcap file synchronously using same detection engine."""
        self.mode = "pcap"
        self.state = DetectionState(get_config())
        self.session = MonitoringSession.objects.create(interface="pcap", mode="pcap", pcap_name=pcap_path.name)
        start_ts = time.perf_counter()
        pkts = rdpcap(str(pcap_path))
        for pkt in pkts:
            self._handle_packet(pkt, record_session=True)
        # processing_ms_total already accumulated per packet; just close session
        if self.session:
            self.session.is_active = False
            self.session.ended_at = timezone.now()
            self.session.save(update_fields=["is_active", "ended_at"])
            self.session = None
        self.mode = "live"

    def _handle_packet(self, pkt, record_session=True):
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
        t0 = time.perf_counter()
        alerts = detect(record, self.state)
        dt_ms = int((time.perf_counter() - t0) * 1000)
        if self.session and record_session:
            self.session.packet_count += 1
            self.session.processing_ms_total += dt_ms
            self.session.save(update_fields=["packet_count", "processing_ms_total"])
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
            if self.session and record_session:
                self.session.alert_count += 1
                self.session.save(update_fields=["alert_count"])
