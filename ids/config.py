from dataclasses import dataclass
import os


@dataclass
class Config:
    db_path: str = os.environ.get("IDS_DB_PATH", "ids.db")
    alert_window_seconds: int = int(os.environ.get("IDS_ALERT_WINDOW", "10"))
    port_scan_threshold: int = int(os.environ.get("IDS_PORT_SCAN_THRESHOLD", "15"))
    syn_flood_threshold: int = int(os.environ.get("IDS_SYN_FLOOD_THRESHOLD", "50"))
    icmp_flood_threshold: int = int(os.environ.get("IDS_ICMP_FLOOD_THRESHOLD", "40"))
    enable_blocking: bool = os.environ.get("IDS_ENABLE_BLOCKING", "false").lower() == "true"
    smtp_server: str | None = os.environ.get("IDS_SMTP_SERVER")
    smtp_port: int = int(os.environ.get("IDS_SMTP_PORT", "587"))
    smtp_user: str | None = os.environ.get("IDS_SMTP_USER")
    smtp_password: str | None = os.environ.get("IDS_SMTP_PASSWORD")
    smtp_recipient: str | None = os.environ.get("IDS_SMTP_RECIPIENT")
    simulate_traffic: bool = os.environ.get("IDS_SIMULATE", "true").lower() == "true"


DEFAULT_CONFIG = Config()
