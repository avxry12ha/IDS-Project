from __future__ import annotations

import random
from datetime import datetime

from .detector import PacketSummary


DOMAINS = [
    "portal.smartstadium.local",
    "ticketing.smartstadium.local",
    "cdn.smartstadium.local",
    "security.vendor.example",
    "streaming.partner.example",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"]


def generate_packet() -> PacketSummary:
    protocol = random.choice(PROTOCOLS)
    dst_port = random.randint(20, 1024) if protocol in {"TCP", "UDP"} else None
    src_port = random.randint(1024, 65000)
    syn_flag = protocol == "TCP" and random.random() < 0.2
    src_ip = f"10.0.0.{random.randint(1, 50)}"
    dst_ip = f"10.0.1.{random.randint(1, 50)}"
    bytes_count = random.randint(64, 1500)
    dns_query = None
    http_host = None
    tls_sni = None
    tls_version = None
    tls_cipher = None

    if protocol == "DNS":
        dst_port = 53
        dns_query = random.choice(DOMAINS)
    elif protocol == "HTTP":
        dst_port = 80
        http_host = random.choice(DOMAINS)
    elif protocol == "HTTPS":
        dst_port = 443
        tls_sni = random.choice(DOMAINS)
        tls_version = random.choice(["TLS1.2", "TLS1.3"])
        tls_cipher = random.choice(["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"])

    return PacketSummary(
        timestamp=datetime.utcnow(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        syn_flag=syn_flag,
        bytes_count=bytes_count,
        dns_query=dns_query,
        http_host=http_host,
        tls_sni=tls_sni,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
    )


def generate_attack_packet(attack_type: str, offender_ip: str) -> PacketSummary:
    src_port = random.randint(1024, 65000)
    dst_port = random.randint(1, 1024)
    protocol = "TCP"
    syn_flag = False
    dns_query = None
    http_host = None
    tls_sni = None
    tls_version = None
    tls_cipher = None

    if attack_type == "port_scan":
        protocol = "TCP"
        dst_port = random.randint(1, 1024)
    elif attack_type == "syn_flood":
        protocol = "TCP"
        syn_flag = True
    elif attack_type == "icmp_flood":
        protocol = "ICMP"
        dst_port = None
    elif attack_type == "brute_force":
        protocol = "TCP"
        dst_port = random.choice([22, 23, 3389])
        syn_flag = True
    elif attack_type == "dns_flood":
        protocol = "DNS"
        dst_port = 53
        dns_query = random.choice(DOMAINS)
    elif attack_type == "https_handshake":
        protocol = "HTTPS"
        dst_port = 443
        tls_sni = random.choice(DOMAINS)
        tls_version = random.choice(["TLS1.0", "TLS1.1"])
        tls_cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"

    return PacketSummary(
        timestamp=datetime.utcnow(),
        src_ip=offender_ip,
        dst_ip="10.0.1.100",
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        syn_flag=syn_flag,
        bytes_count=random.randint(64, 1500),
        dns_query=dns_query,
        http_host=http_host,
        tls_sni=tls_sni,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
    )
