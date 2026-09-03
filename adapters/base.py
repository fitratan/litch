import abc
from typing import Dict, Any, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

class BaseONTAdapter(abc.ABC):
    """
    Base class for vendor-specific ONT adapters.
    """
    vendor_name: str = "Generic"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.session_cookie: Optional[str] = None
        self.authenticated_user: Optional[str] = None
        self.authenticated_password: Optional[str] = None

    def create_http_session(self) -> requests.Session:
        from urllib3.util import Retry
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            connect=3,
            read=2,
            status=0,
            backoff_factor=0.15,
            raise_on_status=False
        )
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retry_strategy
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        return session

    @abc.abstractmethod
    def detect(self) -> bool:
        """
        Check if the target IP matches this vendor adapter.
        """
        pass

    @abc.abstractmethod
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Attempt authentication on the ONT.
        Returns: (success: bool, message: str)
        """
        pass

    @abc.abstractmethod
    def get_wan_info(self) -> Dict[str, Any]:
        """
        Fetch current WAN configuration and connection status.
        """
        pass

    @abc.abstractmethod
    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Apply WAN settings (PPPoE / IPoE / Bridge, VLAN, Credentials, TR-069).
        Returns: (success: bool, message: str)
        """
        pass

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Enable or disable physical LAN ports (LAN1 - LAN4).
        lan_config: {"enable": bool, "ports": {"lan1": bool, "lan2": bool, "lan3": bool, "lan4": bool}}
        Returns: (success: bool, message: str)
        """
        return False, f"Konfigurasi port LAN belum diimplementasikan untuk {self.vendor_name}"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Add, enable, disable, or modify Multi-SSID (SSID1 - SSID4) and security credentials.
        ssid_config: {
            "ssid_index": int (1..4),
            "enable": bool,
            "ssid_name": str,
            "auth_mode": str ("Open" | "WPA2-PSK" | "WPA/WPA2-PSK"),
            "password": str,
            "hide_ssid": bool,
        }
        Returns: (success: bool, message: str)
        """
        return False, f"Konfigurasi Wi-Fi Multi-SSID belum diimplementasikan untuk {self.vendor_name}"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        """
        Change admin / technician password on the ONT.
        Returns: (success: bool, message: str)
        """
        return False, f"Change password not implemented for {self.vendor_name}"

    def get_optical_power(self) -> Dict[str, Any]:
        """
        Fetch PON optical power info (RX Power, TX Power in dBm, Voltage, Temp).
        Returns:
            {
                "rx_power_dbm": Optional[float],
                "tx_power_dbm": Optional[float],
                "voltage_v": Optional[float],
                "temp_c": Optional[float],
                "bias_current_ma": Optional[float],
                "status": str ("Normal" | "Warning" | "Critical" | "N/A"),
                "raw_text": str
            }
        """
        return {
            "rx_power_dbm": None,
            "tx_power_dbm": None,
            "voltage_v": None,
            "temp_c": None,
            "bias_current_ma": None,
            "status": "N/A",
            "raw_text": ""
        }

    def get_wifi_info(self) -> Dict[str, Any]:
        """
        Fetch current Wi-Fi configuration and SSIDs.
        Returns:
            {
                "ssids": List[Dict[str, Any]],
                "clients_count": Optional[int]
            }
        """
        return {"ssids": [], "clients_count": None}

    def reboot(self) -> Tuple[bool, str]:
        """
        Reboot the ONT if supported.
        """
        return False, "Reboot not implemented for this adapter"

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Burn/save current running configuration as permanent default config (Anti-Reset)
        and/or disable physical hardware reset button.
        lock_config: {
            "burn_default_config": bool (default True),
            "disable_reset_button": bool (default True),
        }
        Returns: (success: bool, message: str)
        """
        return False, f"Fitur Anti-Reset belum diimplementasikan untuk {self.vendor_name}"
