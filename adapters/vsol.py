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
        self._sub_adapter = VSOLV2801Adapter(self.ip, self.port, self.timeout)
        self._sub_adapter.session = self.session
        self._sub_adapter.authenticated_user = self.authenticated_user
        self._sub_adapter.authenticated_password = self.authenticated_password
        return self._sub_adapter

__all__ = [
    "VSOLBaseAdapter",
    "VSOLV2801Adapter",
    "VSOLV2802Adapter",
    "VSOLAdapter",
]
