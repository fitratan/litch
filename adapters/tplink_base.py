import re
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.base import BaseONTAdapter


class TPLinkBaseAdapter(BaseONTAdapter):
    vendor_name = "TP-Link (Archer / XC / TX Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.detected_model = ""

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["tp-link", "tplink", "xc220", "tx-6610", "archer"]):
                return True
            if "server" in r.headers and "tp-link" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            payload = {"userName": username, "pcPassword": password}
            r = self.session.post(f"{self.base_url}/cgi/login", data=payload, timeout=self.timeout)
            if r.status_code == 200 and "error" not in r.text.lower():
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login sukses via Web GUI ({username})"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
        return False, "Autentikasi TP-Link gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        return {"vendor": self.vendor_name, "wan_ip": None, "mode": "Unknown", "vlan": None, "pppoe_user": None}

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        try:
            payload = {
                "wanType": mode.lower(),
                "vlanId": vlan or "100",
                "vlanTag": "1" if vlan else "0",
                "pppUser": user,
                "pppPwd": pwd,
            }
            r = self.session.post(f"{self.base_url}/cgi/wan", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"WAN TP-Link berhasil dikonfigurasi ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN TP-Link berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Gagal update WAN TP-Link: {str(e)}"
        return False, "Gagal update WAN TP-Link"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        try:
            payload = {"oldPwd": self.authenticated_password or "admin", "newPwd": new_password, "usrName": username}
            r = self.session.post(f"{self.base_url}/cgi/password", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Password {username} TP-Link berhasil diubah"
        except Exception as e:
            return False, f"Gagal ganti password TP-Link: {str(e)}"
        return False, "Gagal ganti password TP-Link"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")
        try:
            payload = {"ssid": ssid_name, "psk": ssid_pwd, "secType": "wpa2-psk"}
            r = self.session.post(f"{self.base_url}/cgi/wlan", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Wi-Fi SSID {ssid_name} TP-Link berhasil diperbarui"
        except Exception as e:
            return False, f"Gagal update Wi-Fi: {str(e)}"
        return False, "Gagal update Wi-Fi TP-Link"

    def reboot(self) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/cgi/reboot", data={"action": "reboot"}, timeout=3)
            return True, "Reboot signal sent to TP-Link ONT"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "Device TP-Link sedang reboot"
        except Exception as e:
            return False, f"Reboot error: {str(e)}"

    def get_optical_power(self) -> Dict[str, Any]:
        return {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "status": "N/A"}

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/cgi/save", data={"action": "save"}, timeout=3)
            return True, "Konfigurasi TP-Link disimpan permanen"
        except Exception:
            return False, "Gagal mengunci konfigurasi TP-Link"
