# IDS-Project

Prototype intrusion detection system (IDS) with alerting, optional blocking, and a SOC-style dashboard for live network monitoring.

## Features
- Detects port scans, SYN floods, ICMP floods, brute-force bursts, DNS floods, and suspicious HTTP/HTTPS activity.
- Per-protocol telemetry (ICMP, TCP, UDP, DNS, HTTP, HTTPS) with top talkers and top ports.
- Domain visibility from DNS queries, HTTP Host headers, and TLS SNI.
- Optional automatic IP blocking via `iptables` (Linux only).
- Live SOC dashboard with charts, active attack panel, and alert log.
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
| `IDS_ALERT_WINDOW` | `15` | Detection window size in seconds. |
| `IDS_PORT_SCAN_THRESHOLD` | `20` | Unique ports within window to flag scan. |
| `IDS_SYN_FLOOD_THRESHOLD` | `75` | SYN packets within window to flag flood. |
| `IDS_ICMP_FLOOD_THRESHOLD` | `60` | ICMP packets within window to flag flood. |
| `IDS_BRUTE_FORCE_THRESHOLD` | `25` | Attempts per port within window to flag brute force. |
| `IDS_DNS_FLOOD_THRESHOLD` | `50` | DNS packets within window to flag flood. |
| `IDS_HTTP_SUSPICIOUS_THRESHOLD` | `40` | HTTP requests within window to flag bursts. |
| `IDS_HTTPS_HANDSHAKE_THRESHOLD` | `45` | TLS handshakes within window to flag bursts. |
| `IDS_ALERT_COOLDOWN` | `30` | Cooldown in seconds for duplicate alerts. |
| `IDS_ENABLE_BLOCKING` | `false` | Enable `iptables` blocking. |
| `IDS_SMTP_SERVER` | _(empty)_ | SMTP host for email alerts. |
| `IDS_SMTP_PORT` | `587` | SMTP port. |
| `IDS_SMTP_USER` | _(empty)_ | SMTP username. |
| `IDS_SMTP_PASSWORD` | _(empty)_ | SMTP password. |
| `IDS_SMTP_RECIPIENT` | _(empty)_ | Recipient email address. |
| `IDS_SIMULATE` | `true` | `true` for simulated traffic, `false` for live sniffing. |
| `IDS_ENABLE_HTTPS_INTERCEPTION` | `false` | Enable HTTPS interception toggle. |
| `IDS_HTTPS_INTERCEPTION_MODE` | `passive` | `passive` or `lab`. |
| `IDS_METRICS_WINDOW` | `60` | Rolling metrics window in minutes. |

## API endpoints
- `/api/stats` – aggregate metrics, protocol distribution, and alert counts.
- `/api/alerts` – recent alert history.
- `/api/top-talkers` – most active source/destination pairs.
- `/api/domains` – recently visited domains.
- `/api/protocol-distribution` – summary of protocol counts.

## Live sniffing
Set `IDS_SIMULATE=false` and ensure `scapy` is installed. Packet sniffing usually requires elevated privileges:

```bash
IDS_SIMULATE=false sudo -E python -m ids.app
```

## Notes
- Blocking is best-effort and only supported on Linux with `iptables`.
- Passive TLS inspection extracts SNI, TLS version, and cipher when available.
- Lab HTTPS interception mode is represented in the UI but does not implement a full MITM proxy.
