import re
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.base import BaseONTAdapter


class VSOLBaseAdapter(BaseONTAdapter):
    vendor_name = "VSOL (V2801 / V2802 / V2804 Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.detected_model = ""

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["vsol", "v2801", "v2802", "cortina", "gpon/epon"]):
                return True
            if "server" in r.headers and "vsol" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            payload = {"username": username, "password": password, "btn_login": "Login"}
            r = self.session.post(f"{self.base_url}/boaform/admin/formLogin", data=payload, timeout=self.timeout, allow_redirects=True)
            if "login_failed" in r.text.lower() or "error" in r.text.lower():
                return False, "Invalid Credentials"
            if r.status_code == 200 and ("status" in r.text.lower() or "main.asp" in r.url or "wan" in r.text.lower()):
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login sukses via Web GUI ({username})"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
        return False, "Autentikasi VSOL gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        info = {"vendor": self.vendor_name, "wan_ip": None, "mode": "Unknown", "vlan": None, "pppoe_user": None}
        try:
            r = self.session.get(f"{self.base_url}/status_wan.asp", timeout=self.timeout)
            text = r.text
            u_m = re.search(r'(?:username|user|pppoe_user)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
            if u_m:
                info["pppoe_user"] = u_m.group(1)
            v_m = re.search(r'(?:vlan|vid)["\']?\s*[:=,]\s*["\']?(\d+)["\']?', text, re.I)
            if v_m:
                info["vlan"] = int(v_m.group(1))
            ip_m = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
            valid_ips = [ip for ip in ip_m if not ip.startswith("192.168.1.") and ip not in ["0.0.0.0", "255.255.255.0"]]
            if valid_ips:
                info["wan_ip"] = valid_ips[0]
        except Exception:
            pass
        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        try:
            payload = {
                "wan_mode": mode.lower(),
                "vlan_en": "1" if vlan else "0",
                "vlan_id": vlan or "100",
                "ppp_user": user,
                "ppp_pwd": pwd,
                "save": "Apply"
            }
            r = self.session.post(f"{self.base_url}/boaform/admin/formWan", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"WAN VSOL berhasil dikonfigurasi ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN VSOL berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Gagal update WAN VSOL: {str(e)}"
        return False, "Gagal update WAN VSOL"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        try:
            payload = {"oldpass": self.authenticated_password or "admin", "newpass": new_password, "confpass": new_password, "username": username}
            r = self.session.post(f"{self.base_url}/boaform/admin/formPassword", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Password {username} VSOL berhasil diubah"
        except Exception as e:
            return False, f"Gagal ganti password VSOL: {str(e)}"
        return False, "Gagal ganti password VSOL"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")
        try:
            payload = {"ssid": ssid_name, "pskValue": ssid_pwd, "security_mode": "wpa2", "save": "Apply"}
            r = self.session.post(f"{self.base_url}/boaform/admin/formWlan", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Wi-Fi SSID {ssid_name} VSOL berhasil diperbarui"
        except Exception as e:
            return False, f"Gagal update Wi-Fi: {str(e)}"
        return False, "Gagal update Wi-Fi VSOL"

    def reboot(self) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/boaform/admin/formReboot", data={"reboot": "Reboot"}, timeout=3)
            return True, "Reboot command sent to VSOL ONT"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "Device VSOL sedang reboot"
        except Exception as e:
            return False, f"Reboot error: {str(e)}"

    def get_optical_power(self) -> Dict[str, Any]:
        try:
            r = self.session.get(f"{self.base_url}/status_pon.asp", timeout=self.timeout)
            rx_m = re.search(r'RxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
            tx_m = re.search(r'TxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
            if rx_m:
                return {"rx_power_dbm": rx_m.group(1), "tx_power_dbm": tx_m.group(1) if tx_m else "N/A", "status": "Online"}
        except Exception:
            pass
        return {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "status": "N/A"}

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/boaform/admin/formSaveConfig", data={"save": "Save"}, timeout=3)
            return True, "Konfigurasi VSOL disimpan permanen"
        except Exception:
            return False, "Gagal mengunci konfigurasi VSOL"
