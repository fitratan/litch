from adapters.tplink_base import TPLinkBaseAdapter

class TPLinkXC220Adapter(TPLinkBaseAdapter):
    """Dedicated driver for TP-Link XC220-G3v / Archer XPON."""
    vendor_name = "TP-Link XC220 Dualband (XPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "TP-Link XC220"

