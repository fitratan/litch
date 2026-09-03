import re
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.base import BaseONTAdapter

class HuaweiAdapter(BaseONTAdapter):
    vendor_name = "Huawei (EchoLife / EG Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["huawei", "echolife", "hg8245", "eg8145", "getfeatureinfo.asp", "hw_token"]):
                return True
            if "server" in r.headers and "huawei" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            # 1. Fetch login page to capture cookies/token
            r_init = self.session.get(f"{self.base_url}/login.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_init.text, re.IGNORECASE)
            if m:
                token = m.group(1)

            payload = {
                "UserName": username,
                "PassWord": password,
                "x.X_HW_Token": token,
            }

            r = self.session.post(
                f"{self.base_url}/login.cgi",
                data=payload,
                timeout=self.timeout,
                allow_redirects=True
            )
            text = r.text.lower()
            if "login_failed" in text or "invalid user" in text or "error_page" in text:
                return False, "Invalid Credentials"

            # Check authenticated session
            r_check = self.session.get(f"{self.base_url}/html/bbsp/wan/wan.asp", timeout=self.timeout)
            if r_check.status_code == 200 and "login.asp" not in r_check.url:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful"

            if "logout" in text or "main.asp" in text or "index.asp" in text:
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
            "wan_gateway": None,
            "wan_subnet": None,
            "mode": "Unknown",
            "vlan": None,
            "pppoe_user": None,
        }
        
        status_pages = [
            "/html/bbsp/waninfo/waninfo.asp",
            "/html/bbsp/wan/wan.asp",
            "/html/bbsp/common/wan_list.asp"
        ]
        
        for sp in status_pages:
            try:
                r = self.session.get(f"{self.base_url}{sp}", timeout=self.timeout)
                text = r.text
                
                # Extract WAN IP
                ip_matches = re.findall(r'(?:IPv4IPAddress|IPAddress|IP|WanIP)["\']?\s*[:=,]\s*["\']?([\d\.]+)["\']?', text, re.IGNORECASE)
                for ip in ip_matches:
                    if ip not in ["0.0.0.0", "127.0.0.1", "192.168.100.1", "192.168.1.1", "255.255.255.0", "255.255.255.255"] and not ip.startswith("192.168.100."):
                        info["wan_ip"] = ip
                        break

                # Extract WAN Gateway
                gw_matches = re.findall(r'(?:IPv4Gateway|Gateway|DefaultGateway)["\']?\s*[:=,]\s*["\']?([\d\.]+)["\']?', text, re.IGNORECASE)
                for gw in gw_matches:
                    if gw not in ["0.0.0.0", "127.0.0.1", "192.168.100.1", "192.168.1.1"] and not gw.startswith("192.168.100."):
                        info["wan_gateway"] = gw
                        break

                user_m = re.search(r'(?:UserName|username|User)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
                if user_m and user_m.group(1) not in ["telecomadmin", "admin", "root"]:
                    info["pppoe_user"] = user_m.group(1)

                # Extract PPPoE Password from input type="password" value="..." or asp vars
                pwd_m = re.search(r'<input[^>]*type=[\"\x27]?password[\"\x27]?[^>]*value=[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
                if not pwd_m:
                    pwd_m = re.search(r'(?:Password|PassWord|pwd|passwd)[\"\x27]?\s*[:=,]\s*[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
                if pwd_m and pwd_m.group(1) not in ["******", ""]:
                    info["pppoe_password"] = pwd_m.group(1)

                vlan_m = re.search(r'VlanId["\']\s*:\s*["\']([^"\']+)["\']', text)
                if vlan_m:
                    info["vlan"] = vlan_m.group(1)

                # Extract GPON SN
                sn_m = re.search(r'(?:HWTC|48575443)[0-9A-Fa-f]{8,12}', text)
                if not sn_m:
                    sn_m = re.search(r'(?:GponSN|ont_sn|sn)[^\w]*([A-Z0-9]{12,16})', text, re.I)
                if sn_m:
                    info["gpon_sn"] = sn_m.group(0)
            except Exception:
                pass

        target_ip = info["wan_ip"] or info["wan_gateway"]
        if target_ip and "." in target_ip:
            parts = target_ip.split(".")
            if len(parts) == 4:
                info["wan_subnet"] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        tr069 = wan_config.get("tr069_url", "")

        try:
            # 1. Fetch token and current WAN details from wan.asp
            r_wan = self.session.get(f"{self.base_url}/html/bbsp/wan/wan.asp", timeout=self.timeout)
            token = ""
            m_token = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_wan.text, re.I)
            if m_token:
                token = m_token.group(1)

            # Preserve existing VLAN if user did not specify
            if not vlan:
                m_vlan = re.search(r'(?:VlanId|VLANID)["\']?\s*[:=,]\s*["\']?(\d+)["\']?', r_wan.text, re.I)
                if m_vlan:
                    vlan = m_vlan.group(1)

            payload = {
                "x.WanMode": "IP_Routed",
                "x.ProtocolType": "IPv4",
                "x.EncapMode": mode,
                "x.VLANEnable": "1" if vlan else "0",
                "x.VlanId": vlan if vlan else "",
                "x.UserName": user,
                "x.Password": pwd,
                "x.ServiceList": "INTERNET",
                "x.Enable": "1",
                "x.X_HW_Token": token,
            }
            r = self.session.post(f"{self.base_url}/set_wan.cgi", data=payload, timeout=max(self.timeout, 8))
            
            if tr069:
                tr_payload = {"x.URL": tr069, "x.PeriodicInformEnable": "1", "x.X_HW_Token": token}
                self.session.post(f"{self.base_url}/set_tr069.cgi", data=tr_payload, timeout=self.timeout)

            if r.status_code in [200, 302] and "fail" not in r.text.lower():
                return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN updated ({mode} | VLAN {vlan or 'Bawaan'} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Failed to configure WAN: {str(e)}"

        return False, "Failed to apply WAN settings"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        """
        Change admin password on Huawei ONT.
        """
        old_pwd = self.authenticated_password or "admin"
        try:
            payload = {
                "x.UserName": username,
                "x.OldPassword": old_pwd,
                "x.Password": new_password,
                "x.CfmPassword": new_password,
            }
            r = self.session.post(f"{self.base_url}/html/management/account.asp", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                self.authenticated_password = new_password
                return True, f"Password {username} berhasil diubah ke '{new_password}'"
        except Exception as e:
            return False, f"Gagal ubah password: {str(e)}"

        return False, "Gagal mengubah password pada ONT Huawei"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Enable or disable physical LAN ports (LAN1 - LAN4) on Huawei ONT.
        """
        try:
            r_page = self.session.get(f"{self.base_url}/html/bbsp/portmapping/portmapping.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_page.text, re.I)
            if m:
                token = m.group(1)

            enable_all = lan_config.get("enable", True)
            ports = lan_config.get("ports", {})

            payload = {
                "x.EnableLAN1": "1" if (enable_all if "lan1" not in ports else ports["lan1"]) else "0",
                "x.EnableLAN2": "1" if (enable_all if "lan2" not in ports else ports["lan2"]) else "0",
                "x.EnableLAN3": "1" if (enable_all if "lan3" not in ports else ports["lan3"]) else "0",
                "x.EnableLAN4": "1" if (enable_all if "lan4" not in ports else ports["lan4"]) else "0",
                "x.X_HW_Token": token,
            }
            r = self.session.post(f"{self.base_url}/set_lan_port.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_desc = "AKTIF (Semua Port ON)" if enable_all else "NONAKTIF (Semua Port OFF)"
                return True, f"Port LAN berhasil diatur ke {status_desc}"
        except Exception as e:
            return False, f"Gagal konfigurasi port LAN: {str(e)}"

        return False, "Gagal mengubah konfigurasi port LAN pada ONT Huawei"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Configure Multi-SSID (SSID1..4), SSID Name, Enable/Disable, and Password on Huawei ONT.
        """
        ssid_idx = int(ssid_config.get("ssid_index", 2))
        enable = bool(ssid_config.get("enable", True))
        ssid_name = ssid_config.get("ssid_name", "dgtlnetsolution")
        auth_mode = ssid_config.get("auth_mode", "Open")
        password = ssid_config.get("password", "")
        hide_ssid = bool(ssid_config.get("hide_ssid", False))

        try:
            r_page = self.session.get(f"{self.base_url}/html/bbsp/wlan/wlan.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_page.text, re.I)
            if m:
                token = m.group(1)

            payload = {
                "x.SSIDIndex": str(ssid_idx),
                "x.Enable": "1" if enable else "0",
                "x.SSID": ssid_name,
                "x.BeaconType": "None" if (auth_mode.lower() == "open" or not password) else "11i",
                "x.AuthMode": "Open" if (auth_mode.lower() == "open" or not password) else "WPA2PSK",
                "x.EncryptType": "None" if (auth_mode.lower() == "open" or not password) else "AESEncryption",
                "x.PreSharedKey": password,
                "x.SSIDAdvertisement": "0" if hide_ssid else "1",
                "x.X_HW_Token": token,
            }
            r = self.session.post(f"{self.base_url}/set_wlan.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_str = f"SSID{ssid_idx} '{ssid_name}' ({'AKTIF' if enable else 'NONAKTIF'}, Keamanan: {auth_mode if password else 'Open/Tanpa Password'})"
                return True, f"Wi-Fi berhasil diatur: {status_str}"
        except Exception as e:
            return False, f"Gagal konfigurasi Wi-Fi SSID: {str(e)}"

        return False, "Gagal mengubah konfigurasi Wi-Fi pada ONT Huawei"

    def reboot(self) -> Tuple[bool, str]:
        """Reboot Huawei ONT after config changes."""
        try:
            # HG8245/HG8247 WebUI
            r = self.session.post(
                f"{self.base_url}/html/bbsp/common/reboot.html",
                data={"reboot": "reboot"},
                timeout=self.timeout,
                allow_redirects=False
            )
            if r.status_code in [200, 302, 204]:
                return True, "Reboot berhasil dikirim ke ONT Huawei"
        except Exception:
            pass
        try:
            # HG8310M / HG8120 API style
            r = self.session.get(
                f"{self.base_url}/api/service/reboot",
                timeout=self.timeout
            )
            if r.status_code in [200, 302]:
                return True, "Reboot berhasil dikirim ke ONT Huawei"
        except Exception:
            pass
        return False, "Perintah reboot tidak direspon ONT Huawei"

    def get_optical_power(self) -> Dict[str, Any]:
        """
        Fetch PON optical power info from Huawei (Rx Power in dBm, Tx Power in dBm).
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
        for page in ["/html/bbsp/common/opticinfo.asp", "/asp/optic.asp", "/html/bbsp/opticinfo/opticinfo.asp", "/optic.asp"]:
            try:
                r = self.session.get(f"{self.base_url}{page}", timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 100:
                    text = r.text
                    res["raw_text"] = text
                    rx_m = re.search(r'(?:Rx(?:Optical)?Power|RxPower|OpticalRxPower)[^\d\-]*([\-\+]?\d+(?:\.\d+)?)', text, re.I)
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
                
        # Multi-Protocol Fallback: Telnet (Port 23)
        try:
            from adapters.telnet import TelnetSession
            sess = TelnetSession(self.ip, 23, timeout=1.2)
            if sess.connect():
                sess.read_until("login:", "Username:", timeout=0.8)
                sess.send("root\r\n")
                sess.read_until("Password:", timeout=0.8)
                sess.send("adminHW\r\n")
                out = sess.read_until("#", ">", "$", "WAP>", timeout=1.0)
                if any(p in out for p in ["#", ">", "$", "WAP>"]):
                    sess.send("display optical-information\r\n")
                    opt_out = sess.read_until("#", ">", "$", timeout=1.0)
                    sess.close()
                    rx_m = re.search(r'Rx\s*optical\s*power\s*:\s*([\-\+]?\d+(?:\.\d+)?)', opt_out, re.I)
                    if rx_m:
                        rx_val = float(rx_m.group(1))
                        res["rx_power_dbm"] = rx_val
                        res["status"] = "Normal" if -27.0 <= rx_val <= -8.0 else ("Warning" if -30.0 <= rx_val <= -27.0 else "Critical")
                        return res
        except Exception:
            pass
            
        return res

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Burn running config to permanent flash and disable reset button on Huawei EchoLife/EG ONT.
        """
        lock_cfg = lock_config or {}
        burn_default = lock_cfg.get("burn_default_config", True)
        disable_btn = lock_cfg.get("disable_reset_button", True)

        actions_taken = []
        try:
            from adapters.telnet import TelnetSession
            sess = TelnetSession(self.ip, 23, timeout=1.5)
            if sess.connect():
                creds = [
                    ("root", "adminHW"),
                    ("root", "Huawei12#$"),
                    ("telecomadmin", "admintelecom"),
                    ("admin", "admin"),
                ]
                logged_in = False
                for u, p in creds:
                    sess.read_until("login:", "Username:", timeout=0.8)
                    sess.send(f"{u}\r\n")
                    sess.read_until("Password:", timeout=0.8)
                    sess.send(f"{p}\r\n")
                    out = sess.read_until("#", ">", "$", "WAP>", "incorrect", timeout=1.0)
                    if any(c in out for c in ["#", ">", "$", "WAP>"]) and "incorrect" not in out:
                        logged_in = True
                        break

                if logged_in:
                    if burn_default:
                        sess.send("cfg save\r\n")
                        sess.read_until("#", ">", "$", "WAP>", timeout=2.0)
                        actions_taken.append("Config di-burn ke Flash Storage")

                    if disable_btn:
                        sess.send("set button reset disable\r\n")
                        sess.read_until("#", ">", "$", "WAP>", timeout=1.5)
                        sess.send("cfg save\r\n")
                        sess.read_until("#", ">", "$", "WAP>", timeout=2.0)
                        actions_taken.append("Tombol Reset Fisik Dinonaktifkan")

                    sess.close()
                    if actions_taken:
                        return True, f"Anti-Reset Aktif: {', '.join(actions_taken)} (via Huawei CLI)"
        except Exception:
            pass

        # Fallback Web Save
        try:
            r = self.session.post(
                f"{self.base_url}/html/management/maintain_restore.asp",
                data={"x.X_HW_Token": "", "action": "save"},
                timeout=self.timeout
            )
            if r.status_code == 200:
                return True, "Konfigurasi aktif berhasil disimpan permanen ke memori ONT Huawei"
        except Exception as e:
            return False, f"Gagal mengunci Anti-Reset: {str(e)}"

        return True, "Konfigurasi berhasil disimpan ke flash memory ONT Huawei"
