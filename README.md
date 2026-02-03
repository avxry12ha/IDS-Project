# IDS-Project

Prototype intrusion detection system (IDS) with alerting, optional blocking, and a live dashboard.

## Features
- Detects port scans, SYN floods, and ICMP floods.
- Sends console alerts and optional SMTP notifications.
- Optional automatic IP blocking via `iptables` (Linux only).
- Real-time dashboard with charts for alert distribution and traffic volume.
- Simulation mode so you can run without root privileges.

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ids.app
```

Open <http://localhost:5000> to view the dashboard.

## Configuration
Configure the IDS using environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `IDS_DB_PATH` | `ids.db` | SQLite database path. |
| `IDS_ALERT_WINDOW` | `10` | Detection window size in seconds. |
| `IDS_PORT_SCAN_THRESHOLD` | `15` | Unique ports within window to flag scan. |
| `IDS_SYN_FLOOD_THRESHOLD` | `50` | SYN packets within window to flag flood. |
| `IDS_ICMP_FLOOD_THRESHOLD` | `40` | ICMP packets within window to flag flood. |
| `IDS_ENABLE_BLOCKING` | `false` | Enable `iptables` blocking. |
| `IDS_SMTP_SERVER` | _(empty)_ | SMTP host for email alerts. |
| `IDS_SMTP_PORT` | `587` | SMTP port. |
| `IDS_SMTP_USER` | _(empty)_ | SMTP username. |
| `IDS_SMTP_PASSWORD` | _(empty)_ | SMTP password. |
| `IDS_SMTP_RECIPIENT` | _(empty)_ | Recipient email address. |
| `IDS_SIMULATE` | `true` | `true` for simulated traffic, `false` for live sniffing. |

## Live sniffing
Set `IDS_SIMULATE=false` and ensure `scapy` is installed. Packet sniffing usually requires elevated privileges:

```bash
IDS_SIMULATE=false sudo -E python -m ids.app
```

## Notes
- Blocking is best-effort and only supported on Linux with `iptables`.
- In simulation mode, the IDS generates both normal traffic and attack patterns so the dashboard fills quickly.
