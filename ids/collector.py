from __future__ import annotations

import importlib.util
from datetime import datetime
from typing import Callable, Iterable

from .detector import PacketSummary


SCAPY_AVAILABLE = importlib.util.find_spec("scapy.all") is not None

if SCAPY_AVAILABLE:
    from scapy.all import ICMP, IP, TCP, UDP, sniff


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
            syn_flag = False
            if packet.haslayer(TCP):
                protocol = "TCP"
                dst_port = int(packet[TCP].dport)
                syn_flag = bool(packet[TCP].flags & 0x02)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                dst_port = int(packet[UDP].dport)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            summary = PacketSummary(
                timestamp=datetime.utcnow(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=protocol,
                dst_port=dst_port,
                syn_flag=syn_flag,
                bytes_count=len(packet),
            )
            handler(summary)

        sniff(prn=_process, store=False)


class BatchCollector:
    def __init__(self, packets: Iterable[PacketSummary]) -> None:
        self.packets = packets

    def consume(self, handler: Callable[[PacketSummary], None]) -> None:
        for packet in self.packets:
            handler(packet)
