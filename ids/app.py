from __future__ import annotations

import random
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from flask import Flask, render_template

from .analyzer import TrafficAnalyzer
from .api import APIRouter
from .blocker import Blocker
from .collector import PacketCollector
from .config import DEFAULT_CONFIG
from .detector import Detector, PacketSummary
from .interceptor import HTTPSInterceptor
from .metrics import AlertHistory, DomainRecord, MetricsTracker
from .notifier import Notifier
from .simulator import generate_attack_packet, generate_packet
from .storage import Alert, Storage, TrafficSample


class IDSApp:
    def __init__(self) -> None:
        self.config = DEFAULT_CONFIG
        self.storage = Storage(self.config.db_path)
        self.detector = Detector(
            window_seconds=self.config.alert_window_seconds,
            port_scan_threshold=self.config.port_scan_threshold,
            syn_flood_threshold=self.config.syn_flood_threshold,
            icmp_flood_threshold=self.config.icmp_flood_threshold,
            brute_force_threshold=self.config.brute_force_threshold,
            dns_flood_threshold=self.config.dns_flood_threshold,
            http_suspicious_threshold=self.config.http_suspicious_threshold,
            https_handshake_threshold=self.config.https_handshake_threshold,
        )
        self.metrics = MetricsTracker(window_minutes=self.config.metrics_window_minutes)
        self.alert_history = AlertHistory()
        self.analyzer = TrafficAnalyzer()
        self.notifier = Notifier(
            smtp_server=self.config.smtp_server,
            smtp_port=self.config.smtp_port,
            smtp_user=self.config.smtp_user,
            smtp_password=self.config.smtp_password,
            smtp_recipient=self.config.smtp_recipient,
        )
        self.blocker = Blocker(enabled=self.config.enable_blocking)
        self.interceptor = HTTPSInterceptor(
            enabled=self.config.enable_https_interception,
            mode=self.config.https_interception_mode,
        )
        self.alert_cooldown = timedelta(seconds=self.config.alert_cooldown_seconds)
        self.last_alerted: dict[tuple[str, str], datetime] = {}

    def handle_packet(self, packet: PacketSummary) -> None:
        self.storage.save_traffic_samples(
            [
                TrafficSample(
                    timestamp=packet.timestamp,
                    protocol=packet.protocol,
                    bytes_count=packet.bytes_count,
                )
            ]
        )
        self.metrics.ingest(packet)
        domain_insight = self.analyzer.extract_domain(packet)
        if domain_insight:
            self.metrics.ingest_domain(
                DomainRecord(
                    timestamp=packet.timestamp,
                    domain=domain_insight.domain,
                    source_ip=domain_insight.source_ip,
                    protocol=domain_insight.protocol,
                )
            )

        for result in self.detector.ingest(packet):
            alert_key = (result.alert_type, result.offender_ip)
            last_time = self.last_alerted.get(alert_key)
            if last_time and packet.timestamp - last_time < self.alert_cooldown:
                continue
            alert = Alert(
                timestamp=packet.timestamp,
                src_ip=result.offender_ip,
                dst_ip=result.target_ip,
                protocol=result.protocol,
                alert_type=result.alert_type,
                severity=result.severity,
                category=result.category,
                details=result.details,
                src_port=packet.src_port,
                dst_port=result.dst_port,
            )
            self.storage.save_alert(alert)
            self.metrics.increment_alert(result.alert_type)
            self.alert_history.add(
                {
                    "timestamp": alert.timestamp.isoformat(),
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "protocol": alert.protocol,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "category": alert.category,
                    "details": alert.details,
                    "src_port": alert.src_port,
                    "dst_port": alert.dst_port,
                }
            )
            self.notifier.notify(alert)
            self.blocker.block(result.offender_ip)
            self.last_alerted[alert_key] = packet.timestamp

    def start_collection(self) -> None:
        if self.config.simulate_traffic:
            threading.Thread(target=self._simulate_traffic, daemon=True).start()
        else:
            collector = PacketCollector()
            threading.Thread(
                target=collector.sniff_packets,
                args=(self.handle_packet,),
                daemon=True,
            ).start()

    def _simulate_traffic(self) -> None:
        attack_sources = ["10.0.0.200", "10.0.0.201"]
        while True:
            packet = generate_packet()
            if random.random() < 0.1:
                packet = generate_attack_packet("port_scan", random.choice(attack_sources))
            if random.random() < 0.07:
                packet = generate_attack_packet("syn_flood", random.choice(attack_sources))
            if random.random() < 0.05:
                packet = generate_attack_packet("icmp_flood", random.choice(attack_sources))
            if random.random() < 0.06:
                packet = generate_attack_packet("brute_force", random.choice(attack_sources))
            if random.random() < 0.06:
                packet = generate_attack_packet("dns_flood", random.choice(attack_sources))
            if random.random() < 0.05:
                packet = generate_attack_packet(
                    "https_handshake", random.choice(attack_sources)
                )
            self.handle_packet(packet)
            time.sleep(0.2)


def create_app() -> Flask:
    app = Flask(__name__)
    ids_app = IDSApp()
    ids_app.start_collection()

    api_router = APIRouter(
        metrics=ids_app.metrics,
        alerts=ids_app.alert_history,
        interceptor=ids_app.interceptor,
    )
    app.register_blueprint(api_router.blueprint)

    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="0.0.0.0", port=5000, debug=False)
