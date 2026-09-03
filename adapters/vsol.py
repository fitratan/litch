"""
VSOL ONT Adapters Package & Universal Router
Exports:
- VSOLV2801Adapter: VSOL V2801SG / V2801RD Single Port
- VSOLV2802Adapter: VSOL V2802RH / V2804 Dual Band
- VSOLBaseAdapter: Shared VSOL architecture
- VSOLAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.vsol_base import VSOLBaseAdapter
from adapters.vsol_v2801 import VSOLV2801Adapter
from adapters.vsol_v2802 import VSOLV2802Adapter


class VSOLAdapter(VSOLBaseAdapter):
    """Universal VSOL Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> VSOLBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        model_str = (self.detected_model or "").lower()
        if "2802" in model_str or "2804" in model_str or "dual" in model_str:
            self._sub_adapter = VSOLV2802Adapter(self.ip, self.port, self.timeout)
        else:
            self._sub_adapter = VSOLV2801Adapter(self.ip, self.port, self.timeout)
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
    "VSOLBaseAdapter",
    "VSOLV2801Adapter",
    "VSOLV2802Adapter",
    "VSOLAdapter",
]
