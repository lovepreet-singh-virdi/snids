Smart Network Intrusion Detection System (SNIDS)
================================================

Rule-based TCP IDS with live capture and offline PCAP analysis. Built with Django + Scapy + Chart.js.

What it detects
---------------
- SYN flood - excess SYNs without handshakes -> `SYN_FLOOD`
- TCP reset storm - bursts of RSTs -> `TCP_RESET_SPIKE` / `TCP_RESET_FLOW_ANOMALY`
- Session anomaly / hijack hint - seq/ack jumps or repeated duplicate ACKs -> `POTENTIAL_SESSION_HIJACK`
- Port scan / service sweep - many unique destination ports from one source in a short window -> `PORT_SCAN`

Quick start
-----------
```bash
git clone <repo_url>
cd networking
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```
Open http://localhost:8000/

Capture permissions (live sniffing)
-----------------------------------
- Windows: Install Npcap (WinPcap compatible). Run shell/IDE as Administrator.
- Linux: `sudo` or `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))` (point to venv python).
- macOS: `sudo` (libpcap is built-in).

Interface picker notes
----------------------
- Unusable virtual miniports are hidden; typical choices: `Loopback Pseudo-Interface 1`, `Wi-Fi`, `Ethernet` (Bluetooth if present).
- Loopback is best for simulators/PCAP demos; Wi-Fi/Ethernet for real LAN traffic.

Feature tour (what/why/how)
---------------------------
- Live monitoring: Monitoring -> Live -> select interface -> Start/Stop; session history; End All Active Sessions.
- PCAP analysis: Monitoring -> PCAP -> upload `.pcap/.pcapng`; same rules; records a PCAP session.
- Dashboard: metrics + compact chart grid (alerts by type/severity, TCP flags, packet rate 10m, top IPs, top destination ports, recent alerts, quick how-to).
- Live stats: current session packet/alert counters via status polling.
- Alerts: search/sort/pagination (auto-apply), severity badges, detail view, streaming CSV export.
- Traffic (Wireshark-lite): search/sort/pagination, SYN/RST color cues, flow filter (click DPort), packet detail modal (flow/time/src/dst/ports/flags/len).
- Session detail: per-session alerts/packets (paginated), CSV export, View link from Monitoring.
- Detection settings: tune SYN/RST/seq-jump/port-scan thresholds and cooldown; quick Start/Stop with snackbars.
- About: requirements, safety, interface guidance, team & signature features.

How to generate traffic
-----------------------
- Browse/refresh web pages (Wi-Fi/Ethernet).
- `ping 8.8.8.8 -t` (adds traffic; combine with browsing).
- Simulators (admin shell, venv active):
  - `python scripts\simulate_syn_flood.py` - high-rate SYN flood (800 SYNs, 8 sources, 40 ports).
  - `python scripts\simulate_rst_storm.py` - RST bursts.
  - `python scripts\simulate_session_anomaly.py` - seq jumps + duplicate ACKs.
  - `python scripts\simulate_port_scan.py` - 100 distinct ports from one host.
  - `python scripts\simulate_duplicate_ack_low.py` - small duplicate-ACK burst (low severity).
- PCAP demo: Monitoring -> PCAP -> upload `pcaps/ETH_IPv4_TCP_syn.pcap`.

Demo script (live, about 3-5 minutes)
-------------------------------------
1) Start server (admin shell) and open http://localhost:8000/.
2) Monitoring -> Live -> select Loopback (or Wi-Fi) -> Start.
3) Run one simulator; watch Dashboard/Alerts/Traffic update; then Stop.
4) PCAP demo: Monitoring -> PCAP -> upload sample PCAP -> see alerts/session row.
5) Export CSVs: Alerts -> Export CSV; Session detail -> Export CSV; click any packet row for the detail modal.

Detection defaults (editable in Settings)
-----------------------------------------
- `syn_threshold`: 50 SYNs / 10s
- `handshake_completion_min_ratio`: 0.2
- `rst_threshold`: 20 RSTs / 10s
- `hijack_seq_jump`: 500000
- `port_scan_port_threshold`: 30 unique dst ports / window
- `port_scan_window`: 10s
- `alert_cooldown_seconds`: 30

Performance & reporting tips
----------------------------
- From Monitoring sessions: note `packet_count`, `alert_count`, `processing_ms_total`.
- Record CPU/RAM during a 1-2 minute run.
- CSV exports stream (safe for large data).

Troubleshooting
---------------
- Adapter errors / no packets: ensure Npcap installed, run as Admin, choose real interface (Wi-Fi/Ethernet/Loopback).
- Charts empty: generate traffic (sim/browse/PCAP) then refresh.
- No alerts from sims: lower thresholds (SYN/RST/port-scan) in Settings and rerun.
- "Network interface not found": pick a real adapter; virtual WAN miniports are filtered out.

Safety
------
Capture only on networks you are authorized to monitor. Simulators and sample PCAPs are for local/lab use.

Team & ownership (one core networking feature each, UI + backend)
-----------------------------------------------------------------
- Lovepreet Singh Virdi - SYN flood detection rule and alert surfacing.
- Kunal Rastogi - Port-scan detector wiring plus dashboard/status UX.
- Raman Joshi - Session anomaly (seq/ack jump) detector and Alerts/Traffic drill-down.
- Jill Patel - Duplicate-ACK (low hijack) coverage and PCAP ingest/sims.
- Chirag Sanjaykumar Ray - Adapter discovery/filtering and stop/End All sniffer safety.
