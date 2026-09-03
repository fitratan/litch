"""
TP-Link ONT Adapters Package & Universal Router
Exports:
- TPLinkXC220Adapter: TP-Link XC220-G3v / Archer XPON
- TPLinkBaseAdapter: Shared TP-Link architecture
- TPLinkAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.tplink_base import TPLinkBaseAdapter
from adapters.tplink_xc220 import TPLinkXC220Adapter


class TPLinkAdapter(TPLinkBaseAdapter):
    """Universal TP-Link Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> TPLinkBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        self._sub_adapter = TPLinkXC220Adapter(self.ip, self.port, self.timeout)
        self._sub_adapter.session = self.session
        self._sub_adapter.authenticated_user = self.authenticated_user
        self._sub_adapter.authenticated_password = self.authenticated_password
        return self._sub_adapter

__all__ = [
    "TPLinkBaseAdapter",
    "TPLinkXC220Adapter",
    "TPLinkAdapter",
]
