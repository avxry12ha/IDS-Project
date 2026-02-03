from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class PacketSummary:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int | None
    syn_flag: bool
    bytes_count: int


@dataclass
class DetectionResult:
    alert_type: str
    severity: str
    details: str
    offender_ip: str


class Detector:
    def __init__(
        self,
        window_seconds: int,
        port_scan_threshold: int,
        syn_flood_threshold: int,
        icmp_flood_threshold: int,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.recent_packets: deque[PacketSummary] = deque()

    def ingest(self, packet: PacketSummary) -> list[DetectionResult]:
        self.recent_packets.append(packet)
        self._evict_old(packet.timestamp)
        results: list[DetectionResult] = []
        results.extend(self._detect_port_scan(packet.timestamp))
        results.extend(self._detect_syn_flood(packet.timestamp))
        results.extend(self._detect_icmp_flood(packet.timestamp))
        return results

    def _evict_old(self, now: datetime) -> None:
        while self.recent_packets and now - self.recent_packets[0].timestamp > self.window:
            self.recent_packets.popleft()

    def _detect_port_scan(self, now: datetime) -> list[DetectionResult]:
        port_counts: dict[str, set[int]] = defaultdict(set)
        for packet in self.recent_packets:
            if packet.protocol != "TCP" or packet.dst_port is None:
                continue
            port_counts[packet.src_ip].add(packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, ports in port_counts.items():
            if len(ports) >= self.port_scan_threshold:
                results.append(
                    DetectionResult(
                        alert_type="Port scan",
                        severity="High",
                        details=(
                            f"{len(ports)} unique TCP ports targeted in "
                            f"the last {self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                    )
                )
        return results

    def _detect_syn_flood(self, now: datetime) -> list[DetectionResult]:
        syn_counts: dict[str, int] = defaultdict(int)
        for packet in self.recent_packets:
            if packet.protocol == "TCP" and packet.syn_flag:
                syn_counts[packet.src_ip] += 1
        results: list[DetectionResult] = []
        for src_ip, count in syn_counts.items():
            if count >= self.syn_flood_threshold:
                results.append(
                    DetectionResult(
                        alert_type="SYN flood",
                        severity="Critical",
                        details=(
                            f"{count} SYN packets seen in the last "
                            f"{self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                    )
                )
        return results

    def _detect_icmp_flood(self, now: datetime) -> list[DetectionResult]:
        icmp_counts: dict[str, int] = defaultdict(int)
        for packet in self.recent_packets:
            if packet.protocol == "ICMP":
                icmp_counts[packet.src_ip] += 1
        results: list[DetectionResult] = []
        for src_ip, count in icmp_counts.items():
            if count >= self.icmp_flood_threshold:
                results.append(
                    DetectionResult(
                        alert_type="ICMP flood",
                        severity="High",
                        details=(
                            f"{count} ICMP packets seen in the last "
                            f"{self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                    )
                )
        return results
