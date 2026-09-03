import socket
import requests
from typing import Dict, Any, Tuple, List
from adapters.base import BaseONTAdapter

class MikrotikAdapter(BaseONTAdapter):
    vendor_name = "MikroTik RouterOS"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = requests.Session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def detect(self) -> bool:
        # 1. Check Winbox (8291) or RouterOS API (8728)
        for p in [8291, 8728]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((self.ip, p)) == 0:
                        return True
            except Exception:
                pass

        # 2. Check HTTP / WebFig / RouterOS response
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["mikrotik", "routeros", "webfig", "winbox", "mikrotik routeros"]):
                return True
            if "mikrotik" in r.headers.get("server", "").lower():
                return True
        except Exception:
            pass

        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        # MikroTik login bypassed to avoid rest-api fail logs in RouterOS
        return False, "Login MikroTik dinonaktifkan (Bypass)"

    def get_ip_addresses(self) -> List[Dict[str, Any]]:
        """
        Fetch all configured IP Addresses and interface subnets from MikroTik RouterOS.
        """
        if not self.authenticated_user:
            return []
        try:
            r = self.session.get(
                f"{self.base_url}/rest/ip/address",
                auth=(self.authenticated_user, self.authenticated_password),
                timeout=self.timeout
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return []

    def get_ip_pools(self) -> List[Dict[str, Any]]:
        """
        Fetch all DHCP & PPPoE IP Pools configured in MikroTik.
        """
        if not self.authenticated_user:
            return []
        try:
            r = self.session.get(
                f"{self.base_url}/rest/ip/pool",
                auth=(self.authenticated_user, self.authenticated_password),
                timeout=self.timeout
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return []

    def get_wan_info(self) -> Dict[str, Any]:
        info = {
            "vendor": self.vendor_name,
            "wan_ip": self.ip,
            "gateway": self.ip,
            "wan_gateway": self.ip,
            "netmask": "255.255.255.0",
            "mode": "Gateway / RouterOS",
            "vlan": None,
            "pppoe_user": None,
            "connection_name": "MikroTik Gateway",
            "status": "Active",
            "subnet": f"{self.ip.rsplit('.', 1)[0]}.0/24",
            "wan_subnet": None,
            "ip_addresses": [],
            "ip_pools": [],
        }

        # If authenticated, fetch exact IP addresses & pools configured on MikroTik
        if self.authenticated_user:
            addrs = self.get_ip_addresses()
            pools = self.get_ip_pools()
            info["ip_addresses"] = addrs
            info["ip_pools"] = pools

        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        return False, "MikroTik RouterOS dikelola via Winbox / SSH / API"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        return False, "MikroTik RouterOS dikelola via Winbox / SSH / API"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        return False, "MikroTik RouterOS dikelola via Winbox / SSH / API"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        return False, "MikroTik RouterOS dikelola via Winbox / SSH / API"
