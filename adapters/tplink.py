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

__all__ = [
    "TPLinkBaseAdapter",
    "TPLinkWR840NAdapter",
    "TPLinkXC220Adapter",
    "TPLinkAdapter",
]
