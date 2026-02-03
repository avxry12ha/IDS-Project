from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from .detector import PacketSummary


@dataclass
class DomainRecord:
    timestamp: datetime
    domain: str
    source_ip: str
    protocol: str


class MetricsTracker:
    def __init__(self, window_minutes: int = 60) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.protocol_counts: dict[str, Counter[str]] = defaultdict(Counter)
        self.events: deque[PacketSummary] = deque()
        self.domain_events: deque[DomainRecord] = deque()
        self.alert_counts: Counter[str] = Counter()
        self.tls_handshakes: Counter[str] = Counter()

    def ingest(self, packet: PacketSummary) -> None:
        self.events.append(packet)
        self._evict_old(packet.timestamp)
        bucket = packet.timestamp.strftime("%H:%M")
        self.protocol_counts[bucket][packet.protocol] += 1
        if packet.protocol == "HTTPS":
            self.tls_handshakes[packet.src_ip] += 1

    def ingest_domain(self, record: DomainRecord) -> None:
        self.domain_events.append(record)
        self._evict_domain_old(record.timestamp)

    def increment_alert(self, alert_type: str) -> None:
        self.alert_counts[alert_type] += 1

    def get_protocol_distribution(self) -> dict[str, int]:
        distribution: Counter[str] = Counter()
        for counts in self.protocol_counts.values():
            distribution.update(counts)
        return dict(distribution)

    def get_packets_per_minute(self) -> list[dict[str, object]]:
        return [
            {
                "minute": minute,
                "protocols": dict(counts),
            }
            for minute, counts in sorted(self.protocol_counts.items())
        ]

    def top_sources(self, limit: int = 5) -> list[dict[str, object]]:
        counter: Counter[str] = Counter()
        for packet in self.events:
            counter[packet.src_ip] += 1
        return [
            {"ip": ip, "count": count}
            for ip, count in counter.most_common(limit)
        ]

    def top_destinations(self, limit: int = 5) -> list[dict[str, object]]:
        counter: Counter[str] = Counter()
        for packet in self.events:
            counter[packet.dst_ip] += 1
        return [
            {"ip": ip, "count": count}
            for ip, count in counter.most_common(limit)
        ]

    def top_ports(self, limit: int = 5) -> list[dict[str, object]]:
        counter: Counter[int] = Counter()
        for packet in self.events:
            if packet.dst_port is not None:
                counter[packet.dst_port] += 1
        return [
            {"port": port, "count": count}
            for port, count in counter.most_common(limit)
        ]

    def most_active_talkers(self, limit: int = 5) -> list[dict[str, object]]:
        counter: Counter[tuple[str, str]] = Counter()
        for packet in self.events:
            counter[(packet.src_ip, packet.dst_ip)] += 1
        return [
            {"source": source, "destination": destination, "count": count}
            for (source, destination), count in counter.most_common(limit)
        ]

    def top_tls_sources(self, limit: int = 5) -> list[dict[str, object]]:
        return [
            {"ip": ip, "count": count}
            for ip, count in self.tls_handshakes.most_common(limit)
        ]

    def recent_domains(self, limit: int = 8) -> list[dict[str, object]]:
        records = list(self.domain_events)[-limit:]
        return [
            {
                "timestamp": record.timestamp.isoformat(),
                "domain": record.domain,
                "source_ip": record.source_ip,
                "protocol": record.protocol,
            }
            for record in reversed(records)
        ]

    def _evict_old(self, now: datetime) -> None:
        while self.events and now - self.events[0].timestamp > self.window:
            self.events.popleft()
        self._rebuild_protocol_counts()
        self._rebuild_tls_counts()

    def _evict_domain_old(self, now: datetime) -> None:
        while self.domain_events and now - self.domain_events[0].timestamp > self.window:
            self.domain_events.popleft()

    def _rebuild_protocol_counts(self) -> None:
        self.protocol_counts = defaultdict(Counter)
        for packet in self.events:
            bucket = packet.timestamp.strftime("%H:%M")
            self.protocol_counts[bucket][packet.protocol] += 1

    def _rebuild_tls_counts(self) -> None:
        self.tls_handshakes = Counter()
        for packet in self.events:
            if packet.protocol == "HTTPS":
                self.tls_handshakes[packet.src_ip] += 1


class AlertHistory:
    def __init__(self, limit: int = 200) -> None:
        self.limit = limit
        self.history: deque[dict[str, object]] = deque(maxlen=limit)

    def add(self, payload: dict[str, object]) -> None:
        self.history.appendleft(payload)

    def items(self) -> list[dict[str, object]]:
        return list(self.history)
