# Singleton accessor for sniffer service
sniffer_service = None

def get_sniffer():
    global sniffer_service
    if sniffer_service is None:
        from .sniffers import SnifferService
        sniffer_service = SnifferService()
    return sniffer_service
