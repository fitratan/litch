from adapters.huawei_base import HuaweiBaseAdapter

class HuaweiEG8145Adapter(HuaweiBaseAdapter):
    """Dedicated driver for Huawei EchoLife EG8145 / EG8141 / EG8247 (Dual-Band)."""
    vendor_name = "Huawei EchoLife EG8145 Dualband (GPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Huawei EG8145"

