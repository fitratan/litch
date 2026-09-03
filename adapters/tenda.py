"""
Tenda ONT Adapters Package & Universal Router
Exports:
- TendaHG9Adapter: Tenda HG9 / HG6 / HG3 GPON
- TendaBaseAdapter: Shared Tenda architecture
- TendaAdapter: Universal Auto-Router
"""

from typing import Dict, Any, Tuple, Optional
from adapters.tenda_base import TendaBaseAdapter
from adapters.tenda_hg9 import TendaHG9Adapter


class TendaAdapter(TendaBaseAdapter):
    """Universal Tenda Auto-Detecting Adapter."""
    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> TendaBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter
        self._sub_adapter = TendaHG9Adapter(self.ip, self.port, self.timeout)
        self._sub_adapter.session = self.session
        self._sub_adapter.authenticated_user = self.authenticated_user
        self._sub_adapter.authenticated_password = self.authenticated_password
        return self._sub_adapter

__all__ = [
    "TendaBaseAdapter",
    "TendaHG9Adapter",
    "TendaAdapter",
]
