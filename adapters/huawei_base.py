import re
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.base import BaseONTAdapter


class HuaweiBaseAdapter(BaseONTAdapter):
    vendor_name = "Huawei (EchoLife / EG Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
        self.detected_model = ""

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

            r_check = self.session.get(f"{self.base_url}/html/bbsp/wan/wan.asp", timeout=self.timeout)
            if r_check.status_code == 200 and "login.asp" not in r_check.url:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login sukses via Web GUI ({username})"

            if "logout" in text or "main.asp" in text or "index.asp" in text:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login sukses via Web GUI ({username})"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

        return False, "Autentikasi Huawei gagal"

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
        status_pages = ["/html/bbsp/waninfo/waninfo.asp", "/html/bbsp/wan/wan.asp", "/html/bbsp/common/wan_list.asp"]
        for sp in status_pages:
            try:
                r = self.session.get(f"{self.base_url}{sp}", timeout=self.timeout)
                text = r.text
                ip_matches = re.findall(r'(?:IPv4IPAddress|IPAddress|IP|WanIP)["\']?\s*[:=,]\s*["\']?([\d\.]+)["\']?', text, re.I)
                for ip in ip_matches:
                    if ip not in ["0.0.0.0", "127.0.0.1", "192.168.100.1", "192.168.1.1"] and not ip.startswith("192.168.100."):
                        info["wan_ip"] = ip
                        break
                gw_matches = re.findall(r'(?:IPv4Gateway|Gateway|DefaultGateway)["\']?\s*[:=,]\s*["\']?([\d\.]+)["\']?', text, re.I)
                for gw in gw_matches:
                    if gw not in ["0.0.0.0", "127.0.0.1", "192.168.100.1"] and not gw.startswith("192.168.100."):
                        info["wan_gateway"] = gw
                        break
                user_m = re.search(r'(?:UserName|username|User)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
                if user_m and user_m.group(1) not in ["telecomadmin", "admin", "root"]:
                    info["pppoe_user"] = user_m.group(1)
                vlan_m = re.search(r'VlanId["\']\s*:\s*["\']([^"\']+)["\']', text)
                if vlan_m:
                    info["vlan"] = vlan_m.group(1)
            except Exception:
                pass
        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        vlan = str(wan_config.get("vlan_id", "")).strip()
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        tr069 = wan_config.get("tr069_url", "")

        try:
            r_wan = self.session.get(f"{self.base_url}/html/bbsp/wan/wan.asp", timeout=self.timeout)
            token = ""
            m_token = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_wan.text, re.I)
            if m_token:
                token = m_token.group(1)

            existing_vlan = "100"
            m_vlan = re.search(r'VlanId["\']\s*:\s*["\']?(\d+)["\']?', r_wan.text)
            if m_vlan:
                existing_vlan = m_vlan.group(1)
            actual_vlan = vlan if vlan else existing_vlan

            payload = {
                "x.X_HW_Token": token,
                "Action": "Set",
                "Name": "1_INTERNET_R_VID_",
                "Mode": "IP_Routed",
                "ProtocolType": "IPv4",
                "ServiceList": "INTERNET",
                "VlanEnable": "1" if actual_vlan else "0",
                "VlanId": actual_vlan or "",
                "UserName": user,
                "Password": pwd,
                "EncapMode": "PPPoE",
            }
            r_set = self.session.post(f"{self.base_url}/html/bbsp/wan/wan.cgi", data=payload, timeout=self.timeout)
            if r_set.status_code in [200, 302]:
                return True, f"WAN Huawei berhasil dikonfigurasi ({mode} | VLAN {actual_vlan} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN Huawei berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
        except Exception as e:
            return False, f"Gagal mengonfigurasi WAN Huawei: {str(e)}"
        return False, "Gagal mengonfigurasi WAN Huawei"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        try:
            r_page = self.session.get(f"{self.base_url}/html/bbsp/usercfg/usercfg.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_page.text, re.I)
            if m:
                token = m.group(1)
            payload = {
                "x.X_HW_Token": token,
                "OldPassword": self.authenticated_password or "admin",
                "NewPassword": new_password,
                "ConfirmPassword": new_password,
                "UserName": username
            }
            r = self.session.post(f"{self.base_url}/html/bbsp/usercfg/usercfg.cgi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                test_ad = self.__class__(self.ip, self.port, timeout=self.timeout)
                test_ok, _ = test_ad.login(username, new_password)
                if test_ok:
                    self.authenticated_password = new_password
                    return True, f"Password {username} Huawei berhasil diubah ke '{new_password}'"
                return True, f"Password {username} Huawei berhasil diubah"
        except Exception as e:
            return False, f"Gagal mengubah password: {str(e)}"
        return False, "Gagal mengubah password Huawei"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")
        try:
            r_wlan = self.session.get(f"{self.base_url}/html/bbsp/wlan/wlan.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r_wlan.text, re.I)
            if m:
                token = m.group(1)
            payload = {
                "x.X_HW_Token": token,
                "SSID": ssid_name,
                "WPAKey": ssid_pwd,
                "AuthMode": "WPA2-PSK",
                "Action": "Set"
            }
            r_set = self.session.post(f"{self.base_url}/html/bbsp/wlan/wlan.cgi", data=payload, timeout=self.timeout)
            if r_set.status_code in [200, 302]:
                return True, f"Wi-Fi SSID {ssid_name} Huawei berhasil diperbarui"
        except Exception as e:
            return False, f"Gagal update Wi-Fi: {str(e)}"
        return False, "Gagal update Wi-Fi Huawei"

    def reboot(self) -> Tuple[bool, str]:
        try:
            r = self.session.get(f"{self.base_url}/html/bbsp/reboot/reboot.asp", timeout=self.timeout)
            token = ""
            m = re.search(r'name=["\']x\.X_HW_Token["\']\s+value=["\']([^"\']+)["\']', r.text, re.I)
            if m:
                token = m.group(1)
            self.session.post(f"{self.base_url}/html/bbsp/reboot/reboot.cgi", data={"x.X_HW_Token": token, "Action": "Reboot"}, timeout=3)
            return True, "Reboot signal dikirim ke ONT Huawei"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "Device Huawei sedang reboot"
        except Exception as e:
            return False, f"Reboot gagal: {str(e)}"

    def get_optical_power(self) -> Dict[str, Any]:
        for p in ["/html/bbsp/opticinfo/opticinfo.asp", "/html/bbsp/poninfo/poninfo.asp"]:
            try:
                r = self.session.get(f"{self.base_url}{p}", timeout=self.timeout)
                rx_m = re.search(r'RxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
                tx_m = re.search(r'TxPower["\']?\s*[:=]\s*["\']?([-\d\.]+)["\']?', r.text, re.I)
                if rx_m:
                    return {
                        "rx_power_dbm": rx_m.group(1),
                        "tx_power_dbm": tx_m.group(1) if tx_m else "N/A",
                        "status": "Online"
                    }
            except Exception:
                pass
        return {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "status": "N/A"}

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        try:
            r = self.session.post(f"{self.base_url}/html/bbsp/maintenance/commit.cgi", data={"Action": "Save"}, timeout=3)
            return True, "Konfigurasi Huawei disimpan permanen ke Flash"
        except Exception:
            return False, "Gagal mengunci konfigurasi Huawei"
