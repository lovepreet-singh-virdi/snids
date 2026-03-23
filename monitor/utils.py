import psutil

def list_interfaces():
    result = []
    for name, addrs in psutil.net_if_addrs().items():
        ip = addrs[0].address if addrs else ""
        result.append((name, ip))
    return result
