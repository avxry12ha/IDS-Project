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
    src_port: int | None
    dst_port: int | None
    syn_flag: bool
    bytes_count: int
    dns_query: str | None = None
    http_host: str | None = None
    tls_sni: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None


@dataclass
class DetectionResult:
    alert_type: str
    severity: str
    category: str
    details: str
    offender_ip: str
    target_ip: str
    protocol: str
    dst_port: int | None


class Detector:
    def __init__(
        self,
        window_seconds: int,
        port_scan_threshold: int,
        syn_flood_threshold: int,
        icmp_flood_threshold: int,
        brute_force_threshold: int,
        dns_flood_threshold: int,
        http_suspicious_threshold: int,
        https_handshake_threshold: int,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.brute_force_threshold = brute_force_threshold
        self.dns_flood_threshold = dns_flood_threshold
        self.http_suspicious_threshold = http_suspicious_threshold
        self.https_handshake_threshold = https_handshake_threshold
        self.recent_packets: deque[PacketSummary] = deque()

    def ingest(self, packet: PacketSummary) -> list[DetectionResult]:
        self.recent_packets.append(packet)
        self._evict_old(packet.timestamp)
        results: list[DetectionResult] = []
        results.extend(self._detect_port_scan())
        results.extend(self._detect_syn_flood())
        results.extend(self._detect_icmp_flood())
        results.extend(self._detect_brute_force())
        results.extend(self._detect_dns_flood())
        results.extend(self._detect_http_abuse())
        results.extend(self._detect_https_anomalies())
        return results

    def _evict_old(self, now: datetime) -> None:
        while self.recent_packets and now - self.recent_packets[0].timestamp > self.window:
            self.recent_packets.popleft()

    def _detect_port_scan(self) -> list[DetectionResult]:
        port_counts: dict[str, set[int]] = defaultdict(set)
        latest_targets: dict[str, tuple[str, int]] = {}
        for packet in self.recent_packets:
            if packet.protocol != "TCP" or packet.dst_port is None:
                continue
            port_counts[packet.src_ip].add(packet.dst_port)
            latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, ports in port_counts.items():
            if len(ports) >= self.port_scan_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="Port scan",
                        severity="High",
                        category="Reconnaissance",
                        details=(
                            f"{len(ports)} unique TCP ports targeted in "
                            f"the last {self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="TCP",
                        dst_port=dst_port,
                    )
                )
        return results

    def _detect_syn_flood(self) -> list[DetectionResult]:
        syn_counts: dict[str, int] = defaultdict(int)
        latest_targets: dict[str, tuple[str, int | None]] = {}
        for packet in self.recent_packets:
            if packet.protocol == "TCP" and packet.syn_flag:
                syn_counts[packet.src_ip] += 1
                latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, count in syn_counts.items():
            if count >= self.syn_flood_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="SYN flood",
                        severity="Critical",
                        category="DoS",
                        details=(
                            f"{count} SYN packets seen in the last "
                            f"{self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="TCP",
                        dst_port=dst_port,
                    )
                )
        return results

    def _detect_icmp_flood(self) -> list[DetectionResult]:
        icmp_counts: dict[str, int] = defaultdict(int)
        latest_targets: dict[str, tuple[str, int | None]] = {}
        for packet in self.recent_packets:
            if packet.protocol == "ICMP":
                icmp_counts[packet.src_ip] += 1
                latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, count in icmp_counts.items():
            if count >= self.icmp_flood_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="ICMP flood",
                        severity="High",
                        category="DoS",
                        details=(
                            f"{count} ICMP packets seen in the last "
                            f"{self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="ICMP",
                        dst_port=dst_port,
                    )
                )
        return results

    def _detect_brute_force(self) -> list[DetectionResult]:
        attempts: dict[tuple[str, int], int] = defaultdict(int)
        latest_targets: dict[tuple[str, int], tuple[str, int]] = {}
        for packet in self.recent_packets:
            if packet.protocol != "TCP" or packet.dst_port is None:
                continue
            if not packet.syn_flag:
                continue
            key = (packet.src_ip, packet.dst_port)
            attempts[key] += 1
            latest_targets[key] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for (src_ip, dst_port), count in attempts.items():
            if count >= self.brute_force_threshold:
                target_ip, target_port = latest_targets[(src_ip, dst_port)]
                results.append(
                    DetectionResult(
                        alert_type="Brute force attempts",
                        severity="High",
                        category="Abuse",
                        details=(
                            f"{count} connection attempts to port {dst_port} in "
                            f"the last {self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="TCP",
                        dst_port=target_port,
                    )
                )
        return results

    def _detect_dns_flood(self) -> list[DetectionResult]:
        dns_counts: dict[str, int] = defaultdict(int)
        latest_targets: dict[str, tuple[str, int | None]] = {}
        for packet in self.recent_packets:
            if packet.protocol != "DNS":
                continue
            dns_counts[packet.src_ip] += 1
            latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, count in dns_counts.items():
            if count >= self.dns_flood_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="DNS flood",
                        severity="High",
                        category="DoS",
                        details=(
                            f"{count} DNS requests observed in the last "
                            f"{self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="DNS",
                        dst_port=dst_port,
                    )
                )
        return results

    def _detect_http_abuse(self) -> list[DetectionResult]:
        http_counts: dict[str, int] = defaultdict(int)
        latest_targets: dict[str, tuple[str, int | None]] = {}
        for packet in self.recent_packets:
            if packet.protocol != "HTTP":
                continue
            http_counts[packet.src_ip] += 1
            latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, count in http_counts.items():
            if count >= self.http_suspicious_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="Suspicious HTTP burst",
                        severity="Medium",
                        category="Suspicious Traffic",
                        details=(
                            f"{count} HTTP requests in the last {self.window.seconds} "
                            "seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="HTTP",
                        dst_port=dst_port,
                    )
                )
        return results

    def _detect_https_anomalies(self) -> list[DetectionResult]:
        tls_counts: dict[str, int] = defaultdict(int)
        tls_versions: dict[str, set[str]] = defaultdict(set)
        latest_targets: dict[str, tuple[str, int | None]] = {}
        for packet in self.recent_packets:
            if packet.protocol != "HTTPS":
                continue
            tls_counts[packet.src_ip] += 1
            if packet.tls_version:
                tls_versions[packet.src_ip].add(packet.tls_version)
            latest_targets[packet.src_ip] = (packet.dst_ip, packet.dst_port)
        results: list[DetectionResult] = []
        for src_ip, count in tls_counts.items():
            if count >= self.https_handshake_threshold:
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="Excessive TLS handshakes",
                        severity="Medium",
                        category="Suspicious Traffic",
                        details=(
                            f"{count} TLS handshakes in the last {self.window.seconds} "
                            "seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="HTTPS",
                        dst_port=dst_port,
                    )
                )
            if any(version not in {"TLS1.2", "TLS1.3"} for version in tls_versions[src_ip]):
                target_ip, dst_port = latest_targets[src_ip]
                results.append(
                    DetectionResult(
                        alert_type="Unusual TLS version",
                        severity="Low",
                        category="Suspicious Traffic",
                        details=(
                            "Client offered legacy or uncommon TLS versions in the "
                            f"last {self.window.seconds} seconds."
                        ),
                        offender_ip=src_ip,
                        target_ip=target_ip,
                        protocol="HTTPS",
                        dst_port=dst_port,
                    )
                )
        return results
