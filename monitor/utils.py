import psutil


def list_interfaces():
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = None
        for addr in addrs:
            if getattr(addr, "family", None) == psutil.AF_INET:
                ipv4 = addr.address
                break
        result.append((name, ipv4 or ""))
    return result