"""
Fiberhome ONT Adapters Package & Universal Router
Exports:
- FiberhomeAN5506Adapter: Fiberhome AN5506-04 / AN5506-02
- FiberhomeHG680Adapter: Fiberhome HG680 / GPON series
- FiberhomeBaseAdapter: Shared Fiberhome architecture
- FiberhomeAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.fiberhome_base import FiberhomeBaseAdapter
from adapters.fiberhome_an5506 import FiberhomeAN5506Adapter
from adapters.fiberhome_hg680 import FiberhomeHG680Adapter


class FiberhomeAdapter(FiberhomeBaseAdapter):
    """Universal Fiberhome Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> FiberhomeBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        self._sub_adapter = FiberhomeAN5506Adapter(self.ip, self.port, self.timeout)
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
    "FiberhomeBaseAdapter",
    "FiberhomeAN5506Adapter",
    "FiberhomeHG680Adapter",
    "FiberhomeAdapter",
]
