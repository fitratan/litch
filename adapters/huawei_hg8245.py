from adapters.huawei_base import HuaweiBaseAdapter

class HuaweiHG8245Adapter(HuaweiBaseAdapter):
    """Dedicated driver for Huawei EchoLife HG8245 / HG8546 / HG8310."""
    vendor_name = "Huawei EchoLife HG8245 (GPON ONT)"
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Huawei HG8245"

