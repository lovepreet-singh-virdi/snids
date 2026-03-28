import time
from collections import defaultdict, deque
from django.utils import timezone
from django.conf import settings


class DetectionState:
    def __init__(self, config):
        self.cfg = config
        self.syn_events = defaultdict(deque)      # src_ip -> deque[timestamp]
        self.handshakes = defaultdict(lambda: {"syn": 0, "synack": 0, "ack": 0})
        self.rst_events_src = defaultdict(deque)  # src_ip -> deque[timestamp]
        self.rst_events_flow = defaultdict(deque) # flow -> deque[timestamp]
        self.ack_history = defaultdict(deque)     # flow -> deque[(ts, ack)]
        self.last_direction = {}                  # flow -> 'fwd' or 'rev'
        self.alert_cooldowns = {}                 # key -> last_alert_time

    def within_window(self, dq, window, now):
        while dq and now - (dq[0][0] if isinstance(dq[0], tuple) else dq[0]) > window:
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


def _severity_from_intensity(intensity, base="medium"):
    if intensity >= 3:
        return "critical"
    if intensity == 2:
        return "high"
    if intensity == 1:
        return "medium" if base == "medium" else base
    return "low"


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

    # Flow id and direction tracking
    flow = f"{src}:{packet['src_port']}->{dst}:{packet['dst_port']}"
    rev_flow = f"{dst}:{packet['dst_port']}->{src}:{packet['src_port']}"
    direction = "fwd"
    if rev_flow in state.last_direction:
        direction = "rev"
    state.last_direction[flow] = direction

    # Track handshakes
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
                intensity = 2 if syn_rate >= state.cfg["syn_threshold"] * 2 else 1
                sev = _severity_from_intensity(intensity, base="high")
                key = f"synflood:{src}"
                if not state.should_cooldown(key, now):
                    alerts.append({
                        "type": "SYN_FLOOD",
                        "severity": sev,
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

    # RST detection per source and per flow
    if "R" in flags:
        dq_src = state.rst_events_src[src]
        dq_src.append(now)
        state.within_window(dq_src, state.cfg["rst_window_seconds"], now)

        dq_flow = state.rst_events_flow[flow]
        dq_flow.append(now)
        state.within_window(dq_flow, state.cfg["rst_window_seconds"], now)

        # Source-based spike
        if len(dq_src) >= state.cfg["rst_threshold"]:
            intensity = 2 if len(dq_src) >= state.cfg["rst_threshold"] * 2 else 1
            sev = _severity_from_intensity(intensity, base="medium")
            key = f"rststorm:{src}"
            if not state.should_cooldown(key, now):
                alerts.append({
                    "type": "TCP_RESET_SPIKE",
                    "severity": sev,
                    "src_ip": src,
                    "dst_ip": dst,
                    "description": f"RST spike from {src} count {len(dq_src)} in {state.cfg['rst_window_seconds']}s",
                    "evidence": {"count": len(dq_src)},
                    "dedup_key": key,
                })
        # Flow-based abnormal resets
        if len(dq_flow) >= max(3, state.cfg["rst_threshold"] // 2):
            key = f"rstflow:{flow}"
            if not state.should_cooldown(key, now):
                alerts.append({
                    "type": "TCP_RESET_FLOW_ANOMALY",
                    "severity": "medium",
                    "src_ip": src,
                    "dst_ip": dst,
                    "description": f"Multiple RSTs on flow {flow}",
                    "evidence": {"flow_rst_count": len(dq_flow)},
                    "dedup_key": key,
                })

    # Session anomaly indicators
    if packet.get("seq") is not None and packet.get("ack") is not None:
        # Sequence jump
        if "S" not in flags and "F" not in flags and "R" not in flags:
            if packet["seq"] > state.cfg["hijack_seq_jump"]:
                key = f"hijack_seq:{flow}"
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
        # Duplicate ACKs (possible disruption/hijack hint)
        ack_hist = state.ack_history[flow]
        ack_hist.append((now, packet["ack"]))
        state.within_window(ack_hist, state.cfg["syn_window_seconds"], now)
        if len(ack_hist) >= 3:
            ack_values = [a for (_, a) in ack_hist]
            if len(set(ack_values)) == 1:
                key = f"dup_ack:{flow}"
                if not state.should_cooldown(key, now):
                    alerts.append({
                        "type": "POTENTIAL_SESSION_HIJACK",
                        "severity": "low",
                        "src_ip": src,
                        "dst_ip": dst,
                        "description": "Repeated duplicate ACKs observed on flow.",
                        "evidence": {"ack": packet["ack"], "count": len(ack_hist)},
                        "dedup_key": key,
                    })
    return alerts
