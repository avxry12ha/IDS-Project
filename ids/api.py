from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request

from .interceptor import HTTPSInterceptor
from .metrics import MetricsTracker, AlertHistory


class APIRouter:
    def __init__(
        self,
        metrics: MetricsTracker,
        alerts: AlertHistory,
        interceptor: HTTPSInterceptor,
    ) -> None:
        self.metrics = metrics
        self.alerts = alerts
        self.interceptor = interceptor
        self.blueprint = Blueprint("ids_api", __name__)
        self._register_routes()

    def _register_routes(self) -> None:
        blueprint = self.blueprint

        @blueprint.get("/api/alerts")
        def alerts() -> Any:
            return jsonify(self.alerts.items())

        @blueprint.get("/api/stats")
        def stats() -> Any:
            return jsonify(
                {
                    "protocol_distribution": self.metrics.get_protocol_distribution(),
                    "packets_per_minute": self.metrics.get_packets_per_minute(),
                    "top_sources": self.metrics.top_sources(),
                    "top_destinations": self.metrics.top_destinations(),
                    "top_ports": self.metrics.top_ports(),
                    "top_talkers": self.metrics.most_active_talkers(),
                    "tls_sources": self.metrics.top_tls_sources(),
                    "alert_counts": dict(self.metrics.alert_counts),
                    "interception": self.interceptor.status().__dict__,
                }
            )

        @blueprint.get("/api/top-talkers")
        def top_talkers() -> Any:
            return jsonify(self.metrics.most_active_talkers())

        @blueprint.get("/api/domains")
        def domains() -> Any:
            return jsonify(self.metrics.recent_domains())

        @blueprint.get("/api/protocol-distribution")
        def protocol_distribution() -> Any:
            return jsonify(self.metrics.get_protocol_distribution())

        @blueprint.post("/api/interception")
        def set_interception() -> Any:
            payload = request.get_json(silent=True) or {}
            enabled = bool(payload.get("enabled", self.interceptor.enabled))
            mode = payload.get("mode", self.interceptor.mode)
            self.interceptor.set_enabled(enabled)
            self.interceptor.set_mode(mode)
            return jsonify(self.interceptor.status().__dict__)
