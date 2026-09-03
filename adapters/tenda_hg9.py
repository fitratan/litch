from adapters.tenda_base import TendaBaseAdapter

class TendaHG9Adapter(TendaBaseAdapter):
    """Dedicated driver for Tenda HG9 / HG6 / HG3 GPON."""
    vendor_name = "Tenda HG9 Dualband (GPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Tenda HG9"

