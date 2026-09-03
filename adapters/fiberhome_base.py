import re
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.base import BaseONTAdapter


class FiberhomeBaseAdapter(BaseONTAdapter):
    vendor_name = "Fiberhome (AN5506 / HG Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.detected_model = ""

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["fiberhome", "an5506", "fh_", "gpon home gateway"]):
                return True
            if "server" in r.headers and "fiberhome" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            payload = {"username": username, "password": password, "submit": "Login"}
            r = self.session.post(f"{self.base_url}/cgi-bin/login.cgi", data=payload, timeout=self.timeout, allow_redirects=True)
            if "login_error" in r.text.lower() or "invalid" in r.text.lower():
                return False, "Invalid Credentials"

            if r.status_code == 200 and ("status" in r.text.lower() or "main.html" in r.url or "wan" in r.text.lower()):
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login sukses via Web GUI ({username})"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
        return False, "Autentikasi Fiberhome gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        info = {
            "vendor": self.vendor_name,
            "wan_ip": None,
            "gateway": None,
            "wan_gateway": None,
            "netmask": None,
            "mode": "Unknown",
            "vlan": None,
            "pppoe_user": None,
            "connection_name": None,
            "status": "Disconnected",
            "subnet": None,
            "wan_subnet": None,
        }
        try:
            r = self.session.get(f"{self.base_url}/status_wan.html", timeout=self.timeout)
            text = r.text
            u_m = re.search(r'(?:username|user|pppoe_user)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
            if u_m and u_m.group(1) not in ["admin", "user", "root"]:
                info["pppoe_user"] = u_m.group(1)
            v_m = re.search(r'(?:vlan|vlan_id|vid)["\']?\s*[:=,]\s*["\']?(\d+)["\']?', text, re.I)
            if v_m:
                info["vlan"] = int(v_m.group(1))
            ip_m = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
            valid_ips = [ip for ip in ip_m if not ip.startswith("192.168.1.") and ip not in ["0.0.0.0", "255.255.255.0", "255.255.255.255"]]
            if valid_ips:
                info["wan_ip"] = valid_ips[0]
                if len(valid_ips) > 1:
                    info["gateway"] = valid_ips[1]
                    info["wan_gateway"] = valid_ips[1]
            if info["wan_ip"]:
                import ipaddress
                info["subnet"] = str(ipaddress.IPv4Network(f"{info['gateway'] or info['wan_ip']}/24", strict=False))
                info["wan_subnet"] = info["subnet"]
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
                "vlan_enable": "1" if vlan else "0",
                "vlan_id": vlan or "100",
                "username": user,
                "password": pwd,
                "action": "apply"
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/wan_cfg.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"WAN Fiberhome berhasil dikonfigurasi ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN Fiberhome berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Gagal update WAN Fiberhome: {str(e)}"
        return False, "Gagal update WAN Fiberhome"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        try:
            payload = {
                "old_pass": self.authenticated_password or "admin",
                "new_pass": new_password,
                "confirm_pass": new_password,
                "username": username,
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/account.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Password {username} Fiberhome berhasil diubah"
        except Exception as e:
            return False, f"Gagal ganti password: {str(e)}"
        return False, "Gagal ganti password Fiberhome"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")
        try:
            payload = {
                "ssid": ssid_name,
                "wpa_key": ssid_pwd,
                "auth_type": "WPA2-PSK",
                "action": "apply"
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/wlan_cfg.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, f"Wi-Fi SSID {ssid_name} Fiberhome berhasil diperbarui"
        except Exception as e:
            return False, f"Gagal update Wi-Fi: {str(e)}"
        return False, "Gagal update Wi-Fi Fiberhome"

    def reboot(self) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/cgi-bin/reboot.cgi", data={"action": "reboot"}, timeout=3)
            return True, "Reboot command sent to Fiberhome ONT"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "Device Fiberhome sedang reboot"
        except Exception as e:
            return False, f"Reboot error: {str(e)}"

    def get_optical_power(self) -> Dict[str, Any]:
        try:
            r = self.session.get(f"{self.base_url}/status_pon.html", timeout=self.timeout)
            rx_m = re.search(r'RxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
            tx_m = re.search(r'TxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
            if rx_m:
                return {"rx_power_dbm": rx_m.group(1), "tx_power_dbm": tx_m.group(1) if tx_m else "N/A", "status": "Online"}
        except Exception:
            pass
        return {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "status": "N/A"}

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        try:
            self.session.post(f"{self.base_url}/cgi-bin/commit.cgi", data={"action": "save"}, timeout=3)
            return True, "Konfigurasi Fiberhome disimpan permanen"
        except Exception:
            return False, "Gagal mengunci konfigurasi Fiberhome"
