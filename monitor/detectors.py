import time
from collections import defaultdict, deque
from django.utils import timezone
from django.conf import settings


class DetectionState:
    def __init__(self, config):
        self.cfg = config
        self.syn_events = defaultdict(deque)      # key: src_ip -> deque[timestamp]
        self.handshakes = defaultdict(lambda: {"syn": 0, "synack": 0, "ack": 0})
        self.rst_events = defaultdict(deque)      # key: src_ip -> deque[timestamp]
        self.alert_cooldowns = {}                 # key -> last_alert_time

    def within_window(self, dq, window, now):
        while dq and now - dq[0] > window:
            dq.popleft()

    def should_cooldown(self, key, now):
        last = self.alert_cooldowns.get(key, 0)
        if now - last < self.cfg["alert_cooldown_seconds"]:
            return True
        self.alert_cooldowns[key] = now
        return False


def get_config():
    from .models import DetectionSetting
    try:
        ds = DetectionSetting.objects.latest("updated_at")
        return {
            "syn_threshold": ds.syn_threshold,
            "syn_window_seconds": ds.syn_window_seconds,
            "handshake_completion_min_ratio": ds.handshake_completion_min_ratio,
            "rst_threshold": ds.rst_threshold,
            "rst_window_seconds": ds.rst_window_seconds,
            "hijack_seq_jump": ds.hijack_seq_jump,
            "alert_cooldown_seconds": ds.alert_cooldown_seconds,
        }
    except DetectionSetting.DoesNotExist:
        return settings.DETECTION_DEFAULTS


def detect(packet, state: DetectionState):
    """
    packet: dict with keys src_ip,dst_ip,src_port,dst_port,flags,seq,ack,ts,length
    returns list of alerts dicts
    """
    alerts = []
    now = packet["ts"]
    src = packet["src_ip"]
    dst = packet["dst_ip"]
    flags = packet["flags"]

    # Track handshakes
    flow = f"{src}:{packet['src_port']}->{dst}:{packet['dst_port']}"
    hs = state.handshakes[flow]
    if "S" in flags and "A" not in flags:
        hs["syn"] += 1
        dq = state.syn_events[src]
        dq.append(now)
        state.within_window(dq, state.cfg["syn_window_seconds"], now)
        syn_rate = len(dq)
        if syn_rate >= state.cfg["syn_threshold"]:
            completion = (hs["ack"] / hs["syn"]) if hs["syn"] else 0
            if completion < state.cfg["handshake_completion_min_ratio"]:
                key = f"synflood:{src}"
                if not state.should_cooldown(key, now):
                    alerts.append({
                        "type": "SYN_FLOOD",
                        "severity": "high",
                        "src_ip": src,
                        "dst_ip": dst,
                        "description": f"High SYN rate ({syn_rate}) from {src} with low completion ratio {completion:.2f}",
                        "evidence": {"flow": flow, "syn_rate": syn_rate, "completion": completion},
                        "dedup_key": key,
                    })
    if "S" in flags and "A" in flags:
        hs["synack"] += 1
    if "A" in flags and "S" not in flags:
        hs["ack"] += 1

    # RST detection
    if "R" in flags:
        dq = state.rst_events[src]
        dq.append(now)
        state.within_window(dq, state.cfg["rst_window_seconds"], now)
        if len(dq) >= state.cfg["rst_threshold"]:
            key = f"rststorm:{src}"
            if not state.should_cooldown(key, now):
                alerts.append({
                    "type": "TCP_RESET_SPIKE",
                    "severity": "medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "description": f"RST spike from {src} count {len(dq)} in {state.cfg['rst_window_seconds']}s",
                    "evidence": {"count": len(dq)},
                    "dedup_key": key,
                })

    # Potential session hijack indicator
    if packet.get("seq") and packet.get("ack"):
        if "S" not in flags and "F" not in flags and "R" not in flags:
            if packet["seq"] > state.cfg["hijack_seq_jump"]:
                key = f"hijack:{flow}"
                if not state.should_cooldown(key, now):
                    alerts.append({
                        "type": "POTENTIAL_SESSION_HIJACK",
                        "severity": "medium",
                        "src_ip": src,
                        "dst_ip": dst,
                        "description": "Abnormal sequence number jump detected in established flow.",
                        "evidence": {"seq": packet["seq"], "ack": packet["ack"], "flags": flags},
                        "dedup_key": key,
                    })
    return alerts
