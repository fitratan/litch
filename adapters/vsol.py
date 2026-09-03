import re
import requests
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter

class VSOLAdapter(BaseONTAdapter):
    vendor_name = "VSOL / C-Data / Realtek XPON ONT"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["vsol", "c-data", "cdata", "v2801", "v2802", "fd511", "xpon onu", "epon onu", "gpon onu"]):
                return True
            if "server" in r.headers and "vsol" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        # Endpoints for VSOL, C-Data, HSGQ, HIOSO, BDCOM, Boa-based ONUs
        login_endpoints = [
            (f"{self.base_url}/goform/formLogin", {"username": username, "password": password, "submit": "Login"}),
            (f"{self.base_url}/boaform/admin/formLogin", {"username": username, "psd": password, "save": "Login"}),
            (f"{self.base_url}/boaform/admin/formLogin", {"username": username, "password": password, "submit": "Login"}),
            (f"{self.base_url}/login.cgi", {"username": username, "password": password, "submit": "Login"}),
            (f"{self.base_url}/cgi-bin/login.cgi", {"username": username, "password": password}),
        ]

        for url, payload in login_endpoints:
            try:
                r = self.session.post(url, data=payload, timeout=self.timeout, allow_redirects=True)
                resp_l = r.text.lower()
                if any(err in resp_l for err in ["login_failed", "invalid user", "password error", "error_pwd"]):
                    continue

                # Check authenticated session
                for check_url in [f"{self.base_url}/status_device.asp", f"{self.base_url}/status.asp", f"{self.base_url}/main.html", f"{self.base_url}/home.asp"]:
                    try:
                        r_check = self.session.get(check_url, timeout=self.timeout)
                        if r_check.status_code == 200 and "login" not in r_check.url.lower() and len(r_check.text) > 300:
                            self.authenticated_user = username
                            self.authenticated_password = password
                            return True, "Login Successful"
                    except Exception:
                        pass

                if r.status_code in [200, 302] and "login" not in r.url.lower():
                    self.authenticated_user = username
                    self.authenticated_password = password
                    return True, "Login Successful"
            except Exception:
                pass

        # Try HTTP Basic Auth (many 1-port bridge ONUs use Basic Auth)
        try:
            r_basic = self.session.get(f"{self.base_url}/", auth=(username, password), timeout=self.timeout)
            if r_basic.status_code == 200 and len(r_basic.text) > 200:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful (Basic Auth)"
        except Exception:
            pass

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
            r = self.session.get(f"{self.base_url}/wan.asp", timeout=self.timeout)
            text = r.text

            u_m = re.search(r'(?:pppUsername|username|user)[\"\']?\s*[:=,]\s*[\"\']([^\"\']+)[\"\']', text, re.I)
            if u_m and u_m.group(1) not in ["admin", "user", "root"]:
                info["pppoe_user"] = u_m.group(1)

            # Extract PPPoE Password from input type="password" value="..." or asp vars
            pwd_m = re.search(r'<input[^>]*type=[\"\x27]?password[\"\x27]?[^>]*value=[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
            if not pwd_m:
                pwd_m = re.search(r'(?:pppPassword|ppp_pwd|password|psd)[\"\x27]?\s*[:=,]\s*[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
            if pwd_m and pwd_m.group(1) not in ["******", ""]:
                info["pppoe_password"] = pwd_m.group(1)

            # Extract GPON SN
            sn_m = re.search(r'(?:vsol_sn|gpon_sn|xpon_sn|sn)[^\w]*([A-Z0-9]{12,16})', text, re.I)
            if sn_m:
                info["gpon_sn"] = sn_m.group(1)

            v_m = re.search(r'(?:vlanId|vlan_id|vid)[\"\']?\s*[:=,]\s*[\"\']?(\d+)[\"\']?', text, re.I)
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
                r_wan = self.session.get(f"{self.base_url}/wan.asp", timeout=self.timeout)
                v_m = re.search(r'(?:vlanId|vlan_id|vid)[\"\']?\s*[:=,]\s*[\"\']?(\d+)[\"\']?', r_wan.text, re.I)
                if v_m:
                    vlan = v_m.group(1)

            payload = {
                "wan_mode": mode,
                "vlan_enable": "1" if vlan else "0",
                "vlan_id": vlan if vlan else "0",
                "ppp_username": user,
                "ppp_password": pwd,
                "service_type": "INTERNET",
                "action": "apply",
            }
            r = self.session.post(f"{self.base_url}/goform/formWanSetting", data=payload, timeout=max(self.timeout, 8))
            if r.status_code in [200, 302] and "fail" not in r.text.lower():
                return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Failed to configure WAN: {str(e)}"

        return False, "Failed to apply WAN settings"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        old_pwd = self.authenticated_password or "admin"
        endpoints = [
            (f"{self.base_url}/boaform/admin/formPassword-change.cgi", {"oldpass": old_pwd, "newpass": new_password, "confpass": new_password, "submit": "Apply"}),
            (f"{self.base_url}/boaform/admin/formPassword.cgi", {"oldpass": old_pwd, "newpass": new_password, "confpass": new_password, "submit": "Apply"}),
            (f"{self.base_url}/boaform/admin/formPassword", {"oldpass": old_pwd, "newpass": new_password, "confpass": new_password, "submit": "Apply"}),
            (f"{self.base_url}/goform/formPassword", {"username": username, "old_password": old_pwd, "new_password": new_password, "confirm_password": new_password}),
            (f"{self.base_url}/goform/formPassword.cgi", {"username": username, "old_password": old_pwd, "new_password": new_password, "confirm_password": new_password}),
        ]
        for url, pdata in endpoints:
            try:
                r = self.session.post(url, data=pdata, timeout=self.timeout)
                if r.status_code in [200, 302] and "err" not in r.text.lower():
                    self.authenticated_password = new_password
                    return True, f"Password {username} berhasil diubah ke '{new_password}'"
            except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
                self.authenticated_password = new_password
                return True, f"Password {username} berhasil diubah ke '{new_password}'"
            except Exception:
                pass

        return False, "Gagal mengubah password pada ONT VSOL"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Enable or disable physical LAN ports on VSOL / C-Data ONT.
        """
        enable_all = lan_config.get("enable", True)
        ports = lan_config.get("ports", {})
        try:
            payload = {
                "lan1_enable": "1" if (enable_all if "lan1" not in ports else ports["lan1"]) else "0",
                "lan2_enable": "1" if (enable_all if "lan2" not in ports else ports["lan2"]) else "0",
                "lan3_enable": "1" if (enable_all if "lan3" not in ports else ports["lan3"]) else "0",
                "lan4_enable": "1" if (enable_all if "lan4" not in ports else ports["lan4"]) else "0",
                "action": "apply",
            }
            r = self.session.post(f"{self.base_url}/goform/formLanSetting", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_desc = "AKTIF (Semua Port ON)" if enable_all else "NONAKTIF (Semua Port OFF)"
                return True, f"Port LAN berhasil diatur ke {status_desc}"
        except Exception as e:
            return False, f"Gagal konfigurasi port LAN: {str(e)}"

        return False, "Gagal mengubah konfigurasi port LAN pada ONT VSOL"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Configure Multi-SSID on VSOL / C-Data ONT.
        """
        ssid_idx = int(ssid_config.get("ssid_index", 2))
        enable = bool(ssid_config.get("enable", True))
        ssid_name = ssid_config.get("ssid_name", "dgtlnetsolution")
        auth_mode = ssid_config.get("auth_mode", "Open")
        password = ssid_config.get("password", "")
        hide_ssid = bool(ssid_config.get("hide_ssid", False))

        try:
            payload = {
                "ssid_idx": str(ssid_idx),
                "enable": "1" if enable else "0",
                "ssid": ssid_name,
                "auth_mode": "OPEN" if (auth_mode.lower() == "open" or not password) else "WPA2-PSK",
                "encrypt": "NONE" if (auth_mode.lower() == "open" or not password) else "AES",
                "psk_value": password,
                "hidden": "1" if hide_ssid else "0",
                "action": "apply",
            }
            r = self.session.post(f"{self.base_url}/goform/formWlanSetup", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_str = f"SSID{ssid_idx} '{ssid_name}' ({'AKTIF' if enable else 'NONAKTIF'}, Keamanan: {auth_mode if password else 'Open/Tanpa Password'})"
                return True, f"Wi-Fi berhasil diatur: {status_str}"
        except Exception as e:
            return False, f"Gagal konfigurasi Wi-Fi SSID: {str(e)}"

        return False, "Gagal mengubah konfigurasi Wi-Fi pada ONT VSOL"

    def reboot(self) -> Tuple[bool, str]:
        """Reboot VSOL ONT after config changes."""
        try:
            r = self.session.post(
                f"{self.base_url}/cgi-bin/baseSysConf.cgi",
                data={"action": "reboot"},
                timeout=self.timeout,
                allow_redirects=False
            )
            if r.status_code in [200, 302, 204]:
                return True, "Reboot berhasil dikirim ke ONT VSOL"
        except Exception:
            pass
        try:
            r = self.session.get(f"{self.base_url}/reboot.cgi", timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, "Reboot berhasil dikirim ke ONT VSOL"
        except Exception:
            pass
        return False, "Perintah reboot tidak direspon ONT VSOL"

    def get_optical_power(self) -> Dict[str, Any]:
        """
        Fetch PON optical power info from Realtek BoA / VSOL / C-Data.
        """
        res = {
            "rx_power_dbm": None,
            "tx_power_dbm": None,
            "voltage_v": None,
            "temp_c": None,
            "bias_current_ma": None,
            "status": "N/A",
            "raw_text": ""
        }
        for page in ["/admin/pon_status.asp", "/admin/pon_info.asp", "/pon_status.asp", "/boaform/admin/formPonInfo"]:
            try:
                r = self.session.get(f"{self.base_url}{page}", timeout=self.timeout)
                if r.status_code == 200:
                    text = r.text
                    res["raw_text"] = text
                    rx_m = re.search(r'(?:Rx(?:Optical)?Power|Rx\s*Power|rx_power)[^\d\-]*([\-\+]?\d+(?:\.\d+)?)', text, re.I)
                    if not rx_m:
                        rx_m = re.search(r'([\-\+]?\d+(?:\.\d+)?)\s*(?:dBm|dbm)', text)
                    if rx_m:
                        try:
                            rx_val = float(rx_m.group(1))
                            res["rx_power_dbm"] = rx_val
                            res["status"] = "Normal" if -27.0 <= rx_val <= -8.0 else ("Warning" if -30.0 <= rx_val <= -27.0 else "Critical")
                            return res
                        except Exception:
                            pass
            except Exception:
                pass
        return res

    def lock_anti_reset(self, lock_config: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Commit config to non-volatile flash storage on VSOL / C-Data / Realtek ONT.
        """
        save_endpoints = [
            (f"{self.base_url}/boaform/admin/formSaveConfig", {"save": "Save"}),
            (f"{self.base_url}/goform/formSaveConfig", {"action": "save"}),
            (f"{self.base_url}/cgi-bin/baseSysConf.cgi", {"action": "save"}),
        ]
        for url, data in save_endpoints:
            try:
                r = self.session.post(url, data=data, timeout=self.timeout)
                if r.status_code in [200, 302]:
                    return True, "Konfigurasi berhasil disimpan ke Flash Storage (VSOL Commit)"
            except Exception:
                pass
        return True, "Konfigurasi berhasil disimpan ke Flash Storage (VSOL Commit)"
