"""
TP-Link Router & ONT Adapters Package & Universal Router
Exports:
- TPLinkWR840NAdapter: TP-Link TL-WR840N / TL-WR841N / TL-WR844N / TL-WR940N / Archer C20 / Archer C50
- TPLinkXC220Adapter: TP-Link XC220-G3v / TX-6610 XPON ONT
- TPLinkBaseAdapter: Shared TP-Link architecture
- TPLinkAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.tplink_base import TPLinkBaseAdapter
from adapters.tplink_wr840n import TPLinkWR840NAdapter
from adapters.tplink_xc220 import TPLinkXC220Adapter


class TPLinkAdapter(TPLinkBaseAdapter):
    """Universal TP-Link Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> TPLinkBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        model_str = (self.detected_model or "").lower()
        if any(k in model_str for k in ["xc220", "tx-6610", "gpon", "xpon"]):
            self._sub_adapter = TPLinkXC220Adapter(self.ip, self.port, self.timeout)
        else:
            self._sub_adapter = TPLinkWR840NAdapter(self.ip, self.port, self.timeout)
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
    "TPLinkBaseAdapter",
    "TPLinkWR840NAdapter",
    "TPLinkXC220Adapter",
    "TPLinkAdapter",
]
