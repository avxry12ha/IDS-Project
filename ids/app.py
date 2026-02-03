from __future__ import annotations

import json
import random
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template

from .blocker import Blocker
from .collector import PacketCollector
from .config import DEFAULT_CONFIG
from .detector import Detector, PacketSummary
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
        )
        self.notifier = Notifier(
            smtp_server=self.config.smtp_server,
            smtp_port=self.config.smtp_port,
            smtp_user=self.config.smtp_user,
            smtp_password=self.config.smtp_password,
            smtp_recipient=self.config.smtp_recipient,
        )
        self.blocker = Blocker(enabled=self.config.enable_blocking)
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
        for result in self.detector.ingest(packet):
            alert_key = (result.alert_type, result.offender_ip)
            last_time = self.last_alerted.get(alert_key)
            if last_time and packet.timestamp - last_time < self.detector.window:
                continue
            alert = Alert(
                timestamp=packet.timestamp,
                src_ip=result.offender_ip,
                dst_ip=packet.dst_ip,
                protocol=packet.protocol,
                alert_type=result.alert_type,
                severity=result.severity,
                details=result.details,
            )
            self.storage.save_alert(alert)
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
            if random.random() < 0.05:
                packet = generate_attack_packet("syn_flood", random.choice(attack_sources))
            if random.random() < 0.05:
                packet = generate_attack_packet("icmp_flood", random.choice(attack_sources))
            self.handle_packet(packet)
            time.sleep(0.2)


def create_app() -> Flask:
    app = Flask(__name__)
    ids_app = IDSApp()
    ids_app.start_collection()

    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/api/alerts")
    def alerts() -> Any:
        records = ids_app.storage.fetch_recent_alerts()
        alerts_payload = [dict(record) for record in records]
        return jsonify(alerts_payload)

    @app.route("/api/summary")
    def summary() -> Any:
        alert_counts = [dict(record) for record in ids_app.storage.fetch_alert_counts()]
        traffic_summary = [dict(record) for record in ids_app.storage.fetch_traffic_summary()]
        return jsonify(
            {
                "alert_counts": alert_counts,
                "traffic_summary": traffic_summary,
            }
        )

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="0.0.0.0", port=5000, debug=False)
