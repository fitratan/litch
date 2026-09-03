from adapters.vsol_base import VSOLBaseAdapter

class VSOLV2801Adapter(VSOLBaseAdapter):
    """Dedicated driver for VSOL V2801SG / V2801RD Single Port."""
    vendor_name = "VSOL V2801 (XPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "VSOL V2801"

