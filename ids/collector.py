from __future__ import annotations

import importlib.util
from datetime import datetime
from typing import Callable, Iterable

from .detector import PacketSummary


SCAPY_AVAILABLE = importlib.util.find_spec("scapy.all") is not None
TLS_AVAILABLE = importlib.util.find_spec("scapy.layers.tls.all") is not None

if SCAPY_AVAILABLE:
    from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, sniff
if TLS_AVAILABLE:
    from scapy.layers.tls.all import TLSClientHello


TLS_VERSION_MAP = {
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}


class PacketCollector:
    def __init__(self) -> None:
        self.scapy_available = SCAPY_AVAILABLE

    def sniff_packets(self, handler: Callable[[PacketSummary], None]) -> None:
        if not self.scapy_available:
            raise RuntimeError("Scapy not available. Enable simulation mode instead.")

        def _process(packet) -> None:
            if not packet.haslayer(IP):
                return
            ip_layer = packet[IP]
            protocol = "IP"
            dst_port = None
            src_port = None
            syn_flag = False
            dns_query = None
            http_host = None
            tls_sni = None
            tls_version = None
            tls_cipher = None

            if packet.haslayer(TCP):
                protocol = "TCP"
                dst_port = int(packet[TCP].dport)
                src_port = int(packet[TCP].sport)
                syn_flag = bool(packet[TCP].flags & 0x02)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                dst_port = int(packet[UDP].dport)
                src_port = int(packet[UDP].sport)

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                protocol = "DNS"
                query = packet[DNSQR].qname
                dns_query = query.decode("utf-8").rstrip(".") if query else None

            if packet.haslayer(Raw) and protocol in {"TCP", "UDP"}:
                payload = packet[Raw].load
                if payload:
                    http_host = _extract_http_host(payload)
                    if http_host:
                        protocol = "HTTP"

            if TLS_AVAILABLE and packet.haslayer(TLSClientHello):
                tls_layer = packet[TLSClientHello]
                protocol = "HTTPS"
                tls_version = TLS_VERSION_MAP.get(tls_layer.version, str(tls_layer.version))
                tls_cipher = str(tls_layer.cipher)
                tls_sni = _extract_tls_sni(tls_layer)

            summary = PacketSummary(
                timestamp=datetime.utcnow(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                syn_flag=syn_flag,
                bytes_count=len(packet),
                dns_query=dns_query,
                http_host=http_host,
                tls_sni=tls_sni,
                tls_version=tls_version,
                tls_cipher=tls_cipher,
            )
            handler(summary)

        sniff(prn=_process, store=False)


class BatchCollector:
    def __init__(self, packets: Iterable[PacketSummary]) -> None:
        self.packets = packets

    def consume(self, handler: Callable[[PacketSummary], None]) -> None:
        for packet in self.packets:
            handler(packet)


def _extract_http_host(payload: bytes) -> str | None:
    try:
        text = payload.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return None
    if "Host:" not in text:
        return None
    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


def _extract_tls_sni(tls_layer) -> str | None:
    if not hasattr(tls_layer, "ext"):
        return None
    for ext in tls_layer.ext:
        if hasattr(ext, "servernames"):
            names = ext.servernames
            if names:
                return names[0].servername.decode("utf-8", errors="ignore")
    return None
