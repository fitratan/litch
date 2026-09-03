"""
Tenda Router & ONT Adapters Package & Universal Router
Exports:
- TendaN301Adapter: Tenda N301 / F3 / F6 / F9 / AC10 Wireless Routers
- TendaHG9Adapter: Tenda HG9 / HG6 / HG3 GPON ONT
- TendaBaseAdapter: Shared Tenda architecture
- TendaAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.tenda_base import TendaBaseAdapter
from adapters.tenda_n301 import TendaN301Adapter
from adapters.tenda_hg9 import TendaHG9Adapter


class TendaAdapter(TendaBaseAdapter):
    """Universal Tenda Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> TendaBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        model_str = (self.detected_model or "").lower()
        if any(k in model_str for k in ["hg9", "hg6", "hg3", "gpon", "ont"]):
            self._sub_adapter = TendaHG9Adapter(self.ip, self.port, self.timeout)
        else:
            self._sub_adapter = TendaN301Adapter(self.ip, self.port, self.timeout)
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

__all__ = [
    "TendaBaseAdapter",
    "TendaN301Adapter",
    "TendaHG9Adapter",
    "TendaAdapter",
]
