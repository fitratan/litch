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

__all__ = [
    "FiberhomeBaseAdapter",
    "FiberhomeAN5506Adapter",
    "FiberhomeHG680Adapter",
    "FiberhomeAdapter",
]
