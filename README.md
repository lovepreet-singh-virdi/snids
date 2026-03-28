# Smart Network Intrusion Detection System (SNIDS)

Rule-based TCP intrusion detector with live capture and offline PCAP analysis. Built with Django + Scapy + Chart.js. This guide is written for newcomers so you can clone, run, demo, and report on the project without prior IDS knowledge.

## What it detects (plain English)
- **SYN flood**: Too many TCP "hello" (SYN) packets without completing the handshake → raises `SYN_FLOOD`.
- **TCP reset storm**: Bursts of RST packets that kill connections → raises `TCP_RESET_SPIKE` or flow-level `TCP_RESET_FLOW_ANOMALY`.
- **Session anomaly / hijack hints**: Abnormal sequence jumps or repeated duplicate ACKs → raises `POTENTIAL_SESSION_HIJACK`.

## Quick start (works on Windows/Linux/macOS)
```bash
python -m venv .venv
. .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```
Open http://localhost:8000/

### Capture permissions (must-do for live sniffing)
- **Windows**: Install Npcap (enable “WinPcap compatible mode”). Run shell/IDE **as Administrator** when sniffing.
- **Linux**: Either run with `sudo` *or* give Python caps once: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))` (point to venv python if used).
- **macOS**: Run with `sudo` when sniffing; libpcap is built-in.
If live capture fails, it’s almost always missing privileges or pcap driver.

## Repo layout (who owns what)
- Packet capture & utilities: `monitor/sniffers.py`, `monitor/utils.py`
- Detection logic: `monitor/detectors.py`
- Data models: `monitor/models.py`
- Views/APIs/UI wiring: `monitor/views.py`, `monitor/urls.py`, templates in `monitor/templates/monitor/`
- Frontend JS: `monitor/static/monitor/js/dashboard.js`
- Demo traffic: `scripts/simulate_*.py`

## Feature tour (what/why/how to use)
- **Live monitoring**: Pick an interface and Start/Stop. Purpose: real-time detection. UI: Monitoring → Live → choose interface → Start; badge shows status.
- **PCAP analysis**: Upload a capture file; same rules run offline. Purpose: safe/repeatable demos. UI: Monitoring → PCAP → upload `.pcap/.pcapng` → Analyze.
- **Alerts list + detail**: All detections with severity badges; evidence in detail view. Purpose: triage. UI: Alerts page; click “View”.
- **CSV export**: One-click alerts CSV for reporting. UI: Alerts → Export CSV.
- **Dashboard**: Cards + charts (alerts by type/severity, TCP flag mix, packet rate 10m, top suspicious IPs, recent alerts). Purpose: quick situational awareness.
- **Traffic view**: Last 200 packets (time, src/dst, ports, flags, length). Purpose: debugging/visibility.
- **Monitoring sessions history**: Per run stats (mode live/pcap, interface/pcap name, start/end, packet/alert counts, processing ms, active flag). Purpose: audit & perf tracking.
- **Detection settings**: Tune thresholds/cooldown in UI. Purpose: adapt sensitivity.

## How to demo (step-by-step)
1) Start server and open app.
2) **Live demo** (requires privileges): Monitoring → Live → choose loopback → Start. In another shell run one script at a time:
   - `python scripts/simulate_syn_flood.py` → expect `SYN_FLOOD` alerts.
   - `python scripts/simulate_rst_storm.py` → expect `TCP_RESET_*` alerts.
   - `python scripts/simulate_session_anomaly.py` → expect `POTENTIAL_SESSION_HIJACK` alerts.
   Refresh Dashboard/Alerts/Traffic; stop capture when done.
3) **Offline demo**: Monitoring → PCAP → upload `pcaps/ETH_IPv4_TCP_syn.pcap`; alerts and a “pcap” session row should appear.
4) **Export**: Alerts → Export CSV and open the file to verify.

## Detection defaults (editable in Settings page)
- `syn_threshold`: 50 SYNs / 10s
- `handshake_completion_min_ratio`: 0.2
- `rst_threshold`: 20 RSTs / 10s
- `hijack_seq_jump`: 500000
- `alert_cooldown_seconds`: 30

## Performance checklist (for your report)
- Record per-session `packet_count`, `alert_count`, `processing_ms_total` from Monitoring page.
- Measure CPU/RAM during a 1–2 minute run (Task Manager/top).
- Note alert latency (PacketLog vs SecurityAlert timestamps if you instrument further).

## Troubleshooting
- “Permission denied” / no packets on live: missing Npcap/libpcap or not running with admin/raw-socket rights.
- Charts empty: generate traffic (sim scripts or PCAP) and reload.
- No alerts from simulations: thresholds too high; lower `syn_threshold` or `rst_threshold` in Settings then rerun script.

## Safety
Sniff only on networks you are authorized to monitor. Simulation scripts are for local/loopback lab use.