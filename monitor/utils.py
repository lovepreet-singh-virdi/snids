import socket
import psutil


def list_interfaces():
    """Return list of (name, ipv4) tuples; ipv4 may be empty string."""
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = ""
        for addr in addrs:
            if getattr(addr, "family", None) == socket.AF_INET:
                ipv4 = addr.address or ""
                break
        result.append((name, ipv4))
    return result