"""
ZTE ONT Adapters Package & Universal Router
Exports model-specific adapters for each ZTE ONT series:
- ZTEGM220Adapter: ZTE GM220 / GM220-S (XPON ONT)
- ZTEF663Adapter: ZTE ZXHN F663NV9 / F663NV3A / F663N (XPON/GPON ONT)
- ZTEF609Adapter: ZTE ZXHN F609 / F660 / F620 (GPON ONT)
- ZTEF670Adapter: ZTE ZXHN F670 / F670L / F672Y / F477 (Dual-Band XPON/GPON)
- ZTEBaseAdapter: Shared challenge-response auth, token extraction, and Telnet DB engine
"""

from typing import Dict, Any, Tuple, Optional
from adapters.zte_base import ZTEBaseAdapter, decode_hex
from adapters.zte_gm220 import ZTEGM220Adapter
from adapters.zte_f663 import ZTEF663Adapter
from adapters.zte_f609 import ZTEF609Adapter
from adapters.zte_f670 import ZTEF670Adapter


class ZTEAdapter(ZTEBaseAdapter):
    """
    Universal Auto-Detecting ZTE Adapter.
    Automatically identifies the ZTE ONT hardware model (GM220-S, F663, F609, F670)
    and dispatches operations to the specialized model adapter.
    """

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self._sub_adapter = None

    def _resolve_model_adapter(self) -> ZTEBaseAdapter:
        if self._sub_adapter:
            return self._sub_adapter

        # Check detected model or probe HTTP signature
        model_str = (self.detected_model or "").lower()
        if not model_str:
            try:
                r = self.session.get(f"{self.base_url}/", timeout=1.5)
                model_str = r.text.lower()
            except Exception:
                pass

        if "gm220" in model_str:
            self._sub_adapter = ZTEGM220Adapter(self.ip, self.port, self.timeout)
        elif "f663" in model_str:
            self._sub_adapter = ZTEF663Adapter(self.ip, self.port, self.timeout)
        elif "f609" in model_str or "f660" in model_str:
            self._sub_adapter = ZTEF609Adapter(self.ip, self.port, self.timeout)
        elif "f670" in model_str or "f672" in model_str or "f477" in model_str:
            self._sub_adapter = ZTEF670Adapter(self.ip, self.port, self.timeout)
        else:
            # Default to GM220 adapter (covers 90%+ of modern XPON ONTs)
            self._sub_adapter = ZTEGM220Adapter(self.ip, self.port, self.timeout)

        # Sync session state
        self._sub_adapter.session = self.session
        self._sub_adapter.authenticated_user = self.authenticated_user
        self._sub_adapter.authenticated_password = self.authenticated_password
        self._sub_adapter.session_token = self.session_token
        return self._sub_adapter

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        adapter = self._resolve_model_adapter()
        return adapter.configure_wan(wan_config)

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        adapter = self._resolve_model_adapter()
        return adapter.lock_anti_reset(lock_config)


__all__ = [
    "decode_hex",
    "ZTEBaseAdapter",
    "ZTEGM220Adapter",
    "ZTEF663Adapter",
    "ZTEF609Adapter",
    "ZTEF670Adapter",
    "ZTEAdapter",
]
