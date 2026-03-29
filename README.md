 Smart Network Intrusion Detection System (SNIDS)

Rule-based TCP IDS with live capture and offline PCAP analysis. Built with Django + Scapy + Chart.js. This guide is structured so anyone can clone, run, generate traffic, and demo every feature.

## What it detects (plain English)
- **SYN flood** â€" Excess SYNs without handshakes â†" `SYN_FLOOD`
- **TCP reset storm** â€" Bursts of RSTs â†" `TCP_RESET_SPIKE` / `TCP_RESET_FLOW_ANOMALY`
- **Session anomaly / hijack hint** â€" Seq/ack jumps or repeated duplicate ACKs â†" `POTENTIAL_SESSION_HIJACK`
- **Port scan / service sweep** â€" Many unique destination ports from one source in a short window â†" `PORT_SCAN`

## Quick start
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

### Capture permissions (must-do for live sniffing)
- **Windows**: Install Npcap (check â€œWinPcap compatible modeâ€). Run shell/IDE **as Administrator**.
- **Linux**: Use `sudo` or `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))` (point to venv python).
- **macOS**: Use `sudo` (libpcap is built-in).

### Interface picker notes
- We hide unusable virtual miniports; youâ€™ll typically see: `Loopback Pseudo-Interface 1`, `Wi-Fi`, `Ethernet` (Bluetooth if present).
- Loopback is best for simulators/PCAP demos; Wi-Fi/Ethernet for real LAN traffic.

## Feature tour (what/why/how)
- **Live monitoring**: Monitoring â†" Live â†" select interface â†" Start/Stop; session history; â€œEnd All Active Sessionsâ€.
- **PCAP analysis**: Monitoring â†" PCAP â†" upload `.pcap/.pcapng`; same rules; records a PCAP session.
- **Dashboard**: Metrics + compact chart grid (alerts by type/severity, TCP flags, packet rate 10m, top IPs, top destination ports, recent alerts, quick how-to).
- **Live stats**: Current session packet/alert counters via status polling.
- **Alerts**: Search/sort/pagination (auto-apply), severity badges, detail view, streaming CSV export.
- **Traffic (Wireshark-lite)**: Search/sort/pagination, SYN/RST color cues, flow filter (click DPort), packet detail modal (flow/time/src/dst/ports/flags/len).
- **Session detail**: Per-session alerts/packets (paginated), CSV export, â€œViewâ€ link from Monitoring.
- **Detection settings**: Tune SYN/RST/seq-jump/port-scan thresholds and cooldown; quick Start/Stop with snackbars.
- **About**: Requirements, safety, interface guidance, team & signature features.

## How to generate traffic
- Browse/refresh web pages (Wi-Fi/Ethernet).
- `ping 8.8.8.8 -t` (adds traffic; combine with browsing).
- Simulators (admin shell, venv active):
  - `python scripts\simulate_syn_flood.py` â€" high-rate SYN flood (800 SYNs, 8 sources, 40 ports) to trigger high/critical SYN alerts.
  - `python scripts\simulate_rst_storm.py` â€" RST bursts to trigger reset spike.
  - `python scripts\simulate_session_anomaly.py` â€" seq jumps + duplicate ACKs (medium hijack anomaly).
  - `python scripts\simulate_port_scan.py` â€" 100 distinct ports from one host (port-scan alert, medium/high).
  - `python scripts\simulate_duplicate_ack_low.py` â€" small duplicate-ACK burst (low-severity hijack pattern).
- PCAP demo: Monitoring â†" PCAP â†" upload `pcaps/ETH_IPv4_TCP_syn.pcap`.

## Demo script (live, ~3â€"5 minutes)
1) Start server (admin shell) and open http://localhost:8000/.
2) Monitoring â†" Live â†" select **Loopback** (or Wiâ€‘Fi) â†" Start.
3) Run one simulator; watch Dashboard/Alerts/Traffic update; then Stop.
4) PCAP demo: Monitoring â†" PCAP â†" upload sample PCAP â†" see alerts/session row.
5) Export CSVs: Alerts â†" Export CSV; Session detail â†" Export CSV; click any packet row for the detail modal.

## Detection defaults (editable in Settings)
- `syn_threshold`: 50 SYNs / 10s
- `handshake_completion_min_ratio`: 0.2
- `rst_threshold`: 20 RSTs / 10s
- `hijack_seq_jump`: 500000
- `port_scan_port_threshold`: 30 unique dst ports / window
- `port_scan_window`: 10s
- `alert_cooldown_seconds`: 30

## Performance & reporting tips
- From Monitoring sessions: note `packet_count`, `alert_count`, `processing_ms_total`.
- Record CPU/RAM during a 1â€"2 minute run.
- CSV exports stream (safe for large data).

## Troubleshooting
- Adapter errors / no packets: ensure Npcap installed, run as Admin, choose real interface (Wiâ€‘Fi/Ethernet/Loopback).
- Charts empty: generate traffic (sim/browse/PCAP) then refresh.
- No alerts from sims: lower thresholds (SYN/RST/port-scan) in Settings and rerun.
- â€œNetwork interface not foundâ€: pick a real adapter; virtual WAN miniports are filtered out.

## Safety
Capture only on networks youâ€™re authorized to monitor. Simulators and sample PCAPs are for local/lab use.

## Team & ownership (one core networking feature each, UI + backend)
- Lovepreet Singh Virdi â€" Core detection engine (SYN/RST/hijack + port-scan) and alert surfacing.
- Kunal Rastogi â€" Live capture control/status and dashboard metrics/charts.
- Raman Joshi â€" Alerts/Traffic drill-down UX, flow filters, streaming CSV exports.
- Jill Patel â€" PCAP ingest path and simulator suite (SYN, RST, hijack, port-scan, low dup-ack).
- Chirag Sanjaykumar Ray â€" Adapter discovery/filtering and stop/End All sniffer safety.



