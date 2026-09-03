import re
import requests
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter

class FiberhomeAdapter(BaseONTAdapter):
    vendor_name = "Fiberhome (AN5506 / HG Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

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
            payload = {
                "username": username,
                "password": password,
                "submit": "Login"
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/login.cgi", data=payload, timeout=self.timeout, allow_redirects=True)
            if "login_error" in r.text.lower() or "invalid" in r.text.lower():
                return False, "Invalid Credentials"

            if r.status_code == 200 and ("status" in r.text.lower() or "main.html" in r.url or "wan" in r.text.lower()):
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

        return False, "Login failed"

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

            # Extract PPPoE Password from input type="password" value="..."
            pwd_m = re.search(r'<input[^>]*type=[\"\x27]?password[\"\x27]?[^>]*value=[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
            if not pwd_m:
                pwd_m = re.search(r'(?:Password|password|pwd)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
            if pwd_m and pwd_m.group(1) not in ["******", ""]:
                info["pppoe_password"] = pwd_m.group(1)

            # Extract GPON SN
            sn_m = re.search(r'FHTT[0-9A-Fa-f]{8,12}', text)
            if sn_m:
                info["gpon_sn"] = sn_m.group(0)

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
            # Preserve existing VLAN if user did not specify
            if not vlan:
                r_wan = self.session.get(f"{self.base_url}/wan.html", timeout=self.timeout)
                v_m = re.search(r'(?:vlan|vlan_id|vid)["\']?\s*[:=,]\s*["\']?(\d+)["\']?', r_wan.text, re.I)
                if v_m:
                    vlan = v_m.group(1)

            payload = {
                "ServiceType": "INTERNET",
                "ConnectionType": mode,
                "VlanId": vlan if vlan else "0",
                "EnableVlan": "1" if vlan else "0",
                "Username": user,
                "Password": pwd,
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/wan.cgi", data=payload, timeout=max(self.timeout, 8))
            if r.status_code in [200, 302] and "fail" not in r.text.lower():
                return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Failed to configure WAN: {str(e)}"

        return False, "Failed to apply WAN settings"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        old_pwd = self.authenticated_password or "admin"
        try:
            payload = {
                "username": username,
                "old_password": old_pwd,
                "new_password": new_password,
                "confirm_password": new_password,
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/set_user.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                self.authenticated_password = new_password
                return True, f"Password {username} berhasil diubah ke '{new_password}'"
        except Exception as e:
            return False, f"Gagal ubah password: {str(e)}"

        return False, "Gagal mengubah password pada ONT Fiberhome"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Enable or disable physical LAN ports on Fiberhome ONT.
        """
        enable_all = lan_config.get("enable", True)
        ports = lan_config.get("ports", {})
        try:
            payload = {
                "LAN1_Enable": "1" if (enable_all if "lan1" not in ports else ports["lan1"]) else "0",
                "LAN2_Enable": "1" if (enable_all if "lan2" not in ports else ports["lan2"]) else "0",
                "LAN3_Enable": "1" if (enable_all if "lan3" not in ports else ports["lan3"]) else "0",
                "LAN4_Enable": "1" if (enable_all if "lan4" not in ports else ports["lan4"]) else "0",
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/lan_port.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_desc = "AKTIF (Semua Port ON)" if enable_all else "NONAKTIF (Semua Port OFF)"
                return True, f"Port LAN berhasil diatur ke {status_desc}"
        except Exception as e:
            return False, f"Gagal konfigurasi port LAN: {str(e)}"

        return False, "Gagal mengubah konfigurasi port LAN pada ONT Fiberhome"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Configure Multi-SSID on Fiberhome ONT.
        """
        ssid_idx = int(ssid_config.get("ssid_index", 2))
        enable = bool(ssid_config.get("enable", True))
        ssid_name = ssid_config.get("ssid_name", "dgtlnetsolution")
        auth_mode = ssid_config.get("auth_mode", "Open")
        password = ssid_config.get("password", "")
        hide_ssid = bool(ssid_config.get("hide_ssid", False))

        try:
            payload = {
                "SSID_INDEX": str(ssid_idx),
                "Enable": "1" if enable else "0",
                "SSID": ssid_name,
                "AuthMode": "OPEN" if (auth_mode.lower() == "open" or not password) else "WPAPSKWPA2PSK",
                "EncryptType": "NONE" if (auth_mode.lower() == "open" or not password) else "AES",
                "WPAKey": password,
                "HideSSID": "1" if hide_ssid else "0",
            }
            r = self.session.post(f"{self.base_url}/cgi-bin/wlan_ssid.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_str = f"SSID{ssid_idx} '{ssid_name}' ({'AKTIF' if enable else 'NONAKTIF'}, Keamanan: {auth_mode if password else 'Open/Tanpa Password'})"
                return True, f"Wi-Fi berhasil diatur: {status_str}"
        except Exception as e:
            return False, f"Gagal konfigurasi Wi-Fi SSID: {str(e)}"

        return False, "Gagal mengubah konfigurasi Wi-Fi pada ONT Fiberhome"

    def reboot(self) -> Tuple[bool, str]:
        """Reboot Fiberhome ONT after config changes."""
        try:
            r = self.session.post(
                f"{self.base_url}/cgi-bin/sysconf.cgi",
                data={"action": "reboot"},
                timeout=self.timeout,
                allow_redirects=False
            )
            if r.status_code in [200, 302, 204]:
                return True, "Reboot berhasil dikirim ke ONT Fiberhome"
        except Exception:
            pass
        try:
            r = self.session.get(f"{self.base_url}/boaform/admin/formSystemReboot", timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, "Reboot berhasil dikirim ke ONT Fiberhome"
        except Exception:
            pass
        return False, "Perintah reboot tidak direspon ONT Fiberhome"
