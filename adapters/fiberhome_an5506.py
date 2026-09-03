from adapters.fiberhome_base import FiberhomeBaseAdapter

class FiberhomeAN5506Adapter(FiberhomeBaseAdapter):
    """Dedicated driver for Fiberhome AN5506-04 / AN5506-02."""
    vendor_name = "Fiberhome AN5506 (GPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Fiberhome AN5506"

