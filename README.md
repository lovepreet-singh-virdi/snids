# Smart Network Intrusion Detection System (SNIDS)

> Course Programming Project (Option 2) — Team of 5

## 1. Project Overview
A modular, real-time network intrusion detection system focusing on TCP-based attacks (SYN flooding, TCP reset spikes, potential session hijacking indicators). Built with Django + Scapy, it captures live traffic, applies rule-based detection, stores alerts, and presents results on a web dashboard.

## 2. Team Members and Roles
- **Member 1 – Packet Capture & Networking Module**
  - Files: `monitor/sniffers.py`, `monitor/utils.py`
  - Tasks: interface discovery, live/pcap capture, permissions guidance.
- **Member 2 – Feature Extraction & Data Processing**
  - Files: `monitor/sniffers.py` (packet parsing), `monitor/detectors.py` (state bookkeeping helpers)
  - Tasks: extract TCP fields, maintain per-flow/source counters, sliding windows.
- **Member 3 – Detection Engine (Attack Logic)**
  - Files: `monitor/detectors.py`
  - Tasks: implement rules for SYN flood, RST spike, session-hijack indicators; thresholds + cooldowns.
- **Member 4 – Backend + Database (Django Models/APIs)**
  - Files: `monitor/models.py`, `monitor/views.py`, `monitor/urls.py`, `snids/settings.py`, `snids/urls.py`, `monitor/admin.py`
  - Tasks: models, migrations, JSON endpoints for start/stop/status, settings CRUD, admin wiring.
- **Member 5 – Frontend Dashboard + Visualization**
  - Files: `monitor/templates/monitor/*.html`, `monitor/static/monitor/js/dashboard.js`
  - Tasks: Bootstrap UI, tables, Chart.js visuals, sniffer controls, usability polish.

## 3. System Architecture (simple words)
Packet ? Scapy Sniffer ? Feature extraction (TCP fields, counters) ? Detection Engine (rule checks) ? Alert Manager (dedupe, severity) ? Database (SQLite) ? Django Views/APIs ? Dashboard (Bootstrap + Chart.js).

## 4. Technologies Used
- Python 3.10+
- Django 5.x (web, ORM, admin)
- Scapy (live capture)
- PyShark (optional pcap/tshark fallback)
- SQLite (default DB)
- Bootstrap 5, Chart.js (UI/graphs)
- psutil (interface listing)

## 5. Folder Structure (what lives where)
```
project-root/
+- manage.py
+- requirements.txt
+- README.md
+- snids/               # Django project settings/urls
¦   +- settings.py
¦   +- urls.py
¦   +- wsgi.py
¦   +- asgi.py
+- monitor/             # Main app
¦   +- models.py        # DB models
¦   +- views.py         # Web views & JSON APIs
¦   +- urls.py
¦   +- detectors.py     # Detection logic
¦   +- sniffers.py      # Capture & parsing
¦   +- services.py      # Sniffer singleton
¦   +- utils.py         # Interface listing
¦   +- admin.py         # Django admin hooks
¦   +- templates/monitor/*.html
¦   +- static/monitor/js/dashboard.js
+- scripts/             # Safe local simulation
    +- simulate_syn_flood.py
    +- simulate_rst_storm.py
    +- simulate_session_anomaly.py
```

## 6. Setup Instructions (beginner-friendly)
1) **Install Python** 3.10+ and pip.
2) **Create venv**
```
python -m venv .venv
. .venv/bin/activate     # Windows: .venv\Scripts\activate
```
3) **Install dependencies**
```
pip install -r requirements.txt
```
4) **Database setup**
```
python manage.py migrate
python manage.py createsuperuser  # optional
```
5) **Run Django server**
```
python manage.py runserver 0.0.0.0:8000
```
6) **Permissions for sniffing**
- Linux: run server with sudo or grant `CAP_NET_RAW` to python/scapy.
- Windows: install Npcap; run terminal as Administrator; interface names differ (e.g., "Ethernet", "Wi-Fi").

## 7. How to Run the Project
- Start server (step 5).
- Open `http://localhost:8000`.
- Go to **Settings** page.
- Enter interface name (e.g., `eth0`, `lo`, `Ethernet`) and click **Start**. Status badge updates every 5 seconds.
- Use **Stop** to halt capture.

## 8. How to Use the Dashboard
- **Dashboard**: summary cards, recent alerts, bar chart by type.
- **Alerts**: table with alert list and links to detail view (evidence JSON shown).
- **Traffic**: latest packet summaries (lightweight, no payloads).
- **Settings**: tune thresholds and cooldown; control start/stop.

## 9. Attack Detection (rules)
- **SYN Flood**: count SYNs per source within window; if `syn_count >= syn_threshold` and handshake completion ratio < `handshake_completion_min_ratio`, raise High alert.
- **TCP Reset Spike**: RST count per source in window exceeds `rst_threshold`, raise Medium alert.
- **Potential Session Hijacking Indicator**: large unexpected sequence jump without SYN/FIN/RST in established-looking flow; flagged as Medium (suspicion only).
- **Cooldown**: per-pattern cooldown (`alert_cooldown_seconds`) to avoid duplicates.

## 10. Testing Instructions (safe local only)
- Use loopback or isolated lab network.
- Run while sniffer is active:
```
python scripts/simulate_syn_flood.py
python scripts/simulate_rst_storm.py
python scripts/simulate_session_anomaly.py
```
- Verify alerts appear on Dashboard/Alerts pages. Do **not** target external/public hosts.

## 11. Limitations
- Rule-based only; no ML or DPI payload analysis.
- Relies on accurate timestamps and single-host vantage point.
- May miss slow/low-and-slow attacks; may flag bursts of legitimate traffic as alerts (tune thresholds).
- SQLite not ideal for very high throughput; suitable for classroom demos.

## 12. Future Enhancements
- Add pcap upload/offline analysis mode toggle in UI.
- Per-destination SYN tracking and richer flow state tracking.
- Export alerts to CSV/JSON; add email/webhook notification.
- Basic auth on dashboard; HTTPS termination for real deployments.
- More indicators (FIN scan, Xmas scan) and better hijack heuristics.

## 13. Important Notes
- Run with appropriate privileges for packet capture.
- Keep DEBUG off before any real deployment and restrict `ALLOWED_HOSTS`.
- Use only in authorized, controlled environments.

## 14. Demo Plan (10–15 minutes)
1. Intro slide: problem & objectives.
2. Show architecture diagram (packet ? processing ? detection ? alert ? dashboard).
3. Start monitoring on loopback/eth0 via Settings page.
4. Run `simulate_syn_flood.py`; show new alerts + detail evidence.
5. Run `simulate_rst_storm.py`; highlight alert dedupe/cooldown.
6. Show threshold tuning in Settings; rerun a script to show effect.
7. Stop monitoring; recap limitations and future work.

## 15. Performance Evaluation Pointers (fill after tests)
- Metrics: packets/sec processed; alert delay (PacketLog vs SecurityAlert timestamp); CPU% & RAM during 1–2 min run; alerts per scenario; false positives observed.
- Collection: `sqlite3` counts, manual timing, `top`/`psutil` for resources.
- Table template:
  - Scenario | Packets Sent | Packets Logged | Alerts Raised | Avg Alert Delay (ms) | CPU% | Mem (MB) | Notes
