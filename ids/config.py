from dataclasses import dataclass
import os


@dataclass
class Config:
    db_path: str = os.environ.get("IDS_DB_PATH", "ids.db")
    alert_window_seconds: int = int(os.environ.get("IDS_ALERT_WINDOW", "15"))
    port_scan_threshold: int = int(os.environ.get("IDS_PORT_SCAN_THRESHOLD", "20"))
    syn_flood_threshold: int = int(os.environ.get("IDS_SYN_FLOOD_THRESHOLD", "75"))
    icmp_flood_threshold: int = int(os.environ.get("IDS_ICMP_FLOOD_THRESHOLD", "60"))
    brute_force_threshold: int = int(os.environ.get("IDS_BRUTE_FORCE_THRESHOLD", "25"))
    dns_flood_threshold: int = int(os.environ.get("IDS_DNS_FLOOD_THRESHOLD", "50"))
    http_suspicious_threshold: int = int(os.environ.get("IDS_HTTP_SUSPICIOUS_THRESHOLD", "40"))
    https_handshake_threshold: int = int(
        os.environ.get("IDS_HTTPS_HANDSHAKE_THRESHOLD", "45")
    )
    alert_cooldown_seconds: int = int(os.environ.get("IDS_ALERT_COOLDOWN", "30"))
    enable_blocking: bool = os.environ.get("IDS_ENABLE_BLOCKING", "false").lower() == "true"
    smtp_server: str | None = os.environ.get("IDS_SMTP_SERVER")
    smtp_port: int = int(os.environ.get("IDS_SMTP_PORT", "587"))
    smtp_user: str | None = os.environ.get("IDS_SMTP_USER")
    smtp_password: str | None = os.environ.get("IDS_SMTP_PASSWORD")
    smtp_recipient: str | None = os.environ.get("IDS_SMTP_RECIPIENT")
    simulate_traffic: bool = os.environ.get("IDS_SIMULATE", "true").lower() == "true"
    enable_https_interception: bool = (
        os.environ.get("IDS_ENABLE_HTTPS_INTERCEPTION", "false").lower() == "true"
    )
    https_interception_mode: str = os.environ.get(
        "IDS_HTTPS_INTERCEPTION_MODE", "passive"
    )
    metrics_window_minutes: int = int(os.environ.get("IDS_METRICS_WINDOW", "60"))


DEFAULT_CONFIG = Config()
