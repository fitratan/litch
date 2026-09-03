from adapters.fiberhome_base import FiberhomeBaseAdapter

class FiberhomeHG680Adapter(FiberhomeBaseAdapter):
    """Dedicated driver for Fiberhome HG680 / GPON series."""
    vendor_name = "Fiberhome HG680 (GPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Fiberhome HG680"

