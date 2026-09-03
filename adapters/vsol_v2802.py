from adapters.vsol_base import VSOLBaseAdapter

class VSOLV2802Adapter(VSOLBaseAdapter):
    """Dedicated driver for VSOL V2802RH / V2804 Dual Band."""
    vendor_name = "VSOL V2802 / V2804 Dualband (XPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "VSOL V2802"

