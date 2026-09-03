"""
Huawei ONT Adapters Package & Universal Router
Exports:
- HuaweiHG8245Adapter: Huawei EchoLife HG8245 / HG8546 / HG8310
- HuaweiEG8145Adapter: Huawei EchoLife EG8145 / EG8141 / EG8247
- HuaweiBaseAdapter: Shared Huawei architecture
- HuaweiAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.huawei_base import HuaweiBaseAdapter
from adapters.huawei_hg8245 import HuaweiHG8245Adapter
from adapters.huawei_eg8145 import HuaweiEG8145Adapter


class HuaweiAdapter(HuaweiBaseAdapter):
    """Universal Huawei Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> HuaweiBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        model_str = (self.detected_model or "").lower()
        if "eg8" in model_str:
            self._sub_adapter = HuaweiEG8145Adapter(self.ip, self.port, self.timeout)
        else:
            self._sub_adapter = HuaweiHG8245Adapter(self.ip, self.port, self.timeout)
        self._sub_adapter.session = self.session
        self._sub_adapter.authenticated_user = self.authenticated_user
        self._sub_adapter.authenticated_password = self.authenticated_password
        return self._sub_adapter

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        sub = self._resolve_model_adapter()
        ok, msg = sub.login(username, password)
        self.authenticated_user = sub.authenticated_user
        self.authenticated_password = sub.authenticated_password
        return ok, msg

    def get_wan_info(self) -> Dict[str, Any]:
        return self._resolve_model_adapter().get_wan_info()

    def get_wifi_info(self) -> Dict[str, Any]:
        return self._resolve_model_adapter().get_wifi_info()

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        return self._resolve_model_adapter().configure_wan(wan_config)

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        return self._resolve_model_adapter().change_password(new_password, username)

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        return self._resolve_model_adapter().configure_wlan_ssid(ssid_config)

    def reboot(self) -> Tuple[bool, str]:
        return self._resolve_model_adapter().reboot()

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        return self._resolve_model_adapter().lock_anti_reset(lock_config)

    def get_optical_power(self) -> Dict[str, Any]:
        return self._resolve_model_adapter().get_optical_power()

__all__ = [
    "HuaweiBaseAdapter",
    "HuaweiHG8245Adapter",
    "HuaweiEG8145Adapter",
    "HuaweiAdapter",
]
