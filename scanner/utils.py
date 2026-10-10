"""Helpers: target parsing, DNS resolution, validation, naming."""
import ipaddress
import re
import socket
from datetime import datetime
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    """Accept an IP, a domain, or a full URL and return just the host."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Target is empty.")
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    host = urlparse(raw if "://" in raw else "//" + raw).hostname
    if not host:
        raise ValueError(f"Could not understand target: {raw!r}")
    return host


def resolve_target(host: str):
    """Return (ip, input_was_ip). Raises socket.gaierror if DNS fails."""
    try:
        ipaddress.ip_address(host)
        return host, True
    except ValueError:
        pass
    info = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    return info[0][4][0], False


def validate_port_range(start: int, end: int) -> None:
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Ports must be between 1 and 65535.")
    if start > end:
        raise ValueError("Start port must be less than or equal to end port.")


def is_private_or_local(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


def folder_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def compress_ports(ports) -> str:
    """[1,2,3,5,9,10] -> '1-3, 5, 9-10'"""
    ports = sorted(ports)
    if not ports:
        return "none"
    ranges = []
    start = prev = ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        ranges.append((start, prev))
        start = prev = p
    ranges.append((start, prev))
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)