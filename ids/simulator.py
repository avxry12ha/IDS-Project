from __future__ import annotations

import random
from datetime import datetime

from .detector import PacketSummary


PROTOCOLS = ["TCP", "UDP", "ICMP"]


def generate_packet() -> PacketSummary:
    protocol = random.choice(PROTOCOLS)
    dst_port = random.randint(20, 1024) if protocol in {"TCP", "UDP"} else None
    syn_flag = protocol == "TCP" and random.random() < 0.2
    src_ip = f"10.0.0.{random.randint(1, 50)}"
    dst_ip = f"10.0.1.{random.randint(1, 50)}"
    bytes_count = random.randint(64, 1500)
    return PacketSummary(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        dst_port=dst_port,
        syn_flag=syn_flag,
        bytes_count=bytes_count,
    )


def generate_attack_packet(attack_type: str, offender_ip: str) -> PacketSummary:
    protocol = "TCP" if attack_type in {"port_scan", "syn_flood"} else "ICMP"
    dst_port = random.randint(1, 1024) if protocol == "TCP" else None
    syn_flag = attack_type == "syn_flood"
    return PacketSummary(
        timestamp=datetime.utcnow(),
        src_ip=offender_ip,
        dst_ip="10.0.1.100",
        protocol=protocol,
        dst_port=dst_port,
        syn_flag=syn_flag,
        bytes_count=random.randint(64, 1500),
    )
