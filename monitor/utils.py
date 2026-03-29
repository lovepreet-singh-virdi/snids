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
        lname = name.lower()
        keep = (
            ipv4
            or "loopback" in lname
            or "wi-fi" in lname
            or "wifi" in lname
            or "ethernet" in lname
            or "bluetooth" in lname
        )
        if keep:
            result.append((name, ipv4))
    return result
