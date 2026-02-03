from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from .detector import PacketSummary


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


@dataclass
class DomainInsight:
    domain: str
    source_ip: str
    protocol: str


class TrafficAnalyzer:
    def is_private(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in PRIVATE_NETWORKS)

    def is_outbound(self, packet: PacketSummary) -> bool:
        return self.is_private(packet.src_ip) and not self.is_private(packet.dst_ip)

    def extract_domain(self, packet: PacketSummary) -> Optional[DomainInsight]:
        if packet.dns_query:
            return DomainInsight(
                domain=packet.dns_query,
                source_ip=packet.src_ip,
                protocol="DNS",
            )
        if packet.http_host:
            return DomainInsight(
                domain=packet.http_host,
                source_ip=packet.src_ip,
                protocol="HTTP",
            )
        if packet.tls_sni:
            return DomainInsight(
                domain=packet.tls_sni,
                source_ip=packet.src_ip,
                protocol="HTTPS",
            )
        return None
