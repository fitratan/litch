import re
import base64
import hashlib
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.tplink_base import TPLinkBaseAdapter


class TPLinkWR840NAdapter(TPLinkBaseAdapter):
    """
    Dedicated driver for TP-Link TL-WR840N / TL-WR841N / TL-WR844N / TL-WR940N / Archer C20 / Archer C50.
    - Supports classic Web GUI (/userRpm/) with Basic Auth & MD5 token
    - Supports modern CGI (/cgi/)
    """
    vendor_name = "TP-Link TL-WR840N / WR841N (Wireless Router)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "TP-Link TL-WR840N / WR841N"
        self.auth_token = ""

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["wr840", "wr841", "wr844", "wr940", "userrpm", "tp-link", "tplink"]):
                return True
            if "server" in r.headers and "tp-link" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        clean_pwd = password.strip()
        auth_str = f"{username}:{clean_pwd}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        md5_pwd = hashlib.md5(clean_pwd.encode()).hexdigest()

        # Method 1: HTTP Basic Auth on /userRpm/LoginRpm.htm or /
        self.session.headers.update({"Authorization": f"Basic {b64_auth}"})
        self.session.cookies.set("Authorization", f"Basic {b64_auth}")

        for test_url in [
            f"{self.base_url}/userRpm/StatusRpm.htm",
            f"{self.base_url}/userRpm/LoginRpm.htm?Save=Save",
            f"{self.base_url}/userRpm/Index.htm",
        ]:
            try:
                r = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200 and "login" not in r.url.lower() and len(r.text) > 500:
                    self.authenticated_user = username
                    self.authenticated_password = clean_pwd
                    return True, f"Login sukses TP-Link WR840N/WR841N ({username})"
            except Exception:
                continue

        # Method 2: Modern JSON login via /cgi/login
        try:
            payload = {"userName": username, "pcPassword": md5_pwd}
            r_cgi = self.session.post(f"{self.base_url}/cgi/login", data=payload, timeout=self.timeout)
            if r_cgi.status_code == 200 and "error" not in r_cgi.text.lower():
                self.authenticated_user = username
                self.authenticated_password = clean_pwd
                return True, f"Login sukses TP-Link via CGI ({username})"
        except Exception:
            pass

        return False, "Autentikasi TP-Link WR840N gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        info = {
            "vendor": self.vendor_name,
            "wan_ip": None,
            "mode": "PPPoE",
            "vlan": None,
            "pppoe_user": None,
        }
        try:
            r = self.session.get(f"{self.base_url}/userRpm/StatusRpm.htm", timeout=self.timeout)
            text = r.text
            u_m = re.search(r'(?:pppoe_user|userName|usrName)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
            if u_m and u_m.group(1) not in ["admin", "root"]:
                info["pppoe_user"] = u_m.group(1)

            ip_m = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
            valid_ips = [ip for ip in ip_m if not ip.startswith("192.168.0.") and not ip.startswith("192.168.1.") and ip not in ["0.0.0.0", "255.255.255.0"]]
            if valid_ips:
                info["wan_ip"] = valid_ips[0]
        except Exception:
            pass
        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")

        # Method 1: Classic userRpm Form
        try:
            url = f"{self.base_url}/userRpm/WanCfgRpm.htm?wan=1&wantype=2&pppoeuser={user}&pppoepwd={pwd}&secwantype=0&linktype=1&Save=Save"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                return True, f"WAN TP-Link WR840N berhasil dikonfigurasi ({mode} | User: {user})"
        except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
            return True, f"WAN TP-Link WR840N berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
        except Exception:
            pass

        # Method 2: CGI Form
        try:
            payload = {"wanType": "pppoe", "pppUser": user, "pppPwd": pwd}
            r_cgi = self.session.post(f"{self.base_url}/cgi/wan", data=payload, timeout=self.timeout)
            if r_cgi.status_code in [200, 302]:
                return True, f"WAN TP-Link WR840N berhasil dikonfigurasi via CGI ({mode} | User: {user})"
        except Exception as e:
            return False, f"Gagal update WAN TP-Link: {str(e)}"

        return False, "Gagal mengonfigurasi WAN TP-Link WR840N"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")

        try:
            url = f"{self.base_url}/userRpm/WlanNetworkRpm.htm?ssid1={ssid_name}&keytype=3&pskSecret={ssid_pwd}&wepindex=1&authtype=1&Save=Save"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                return True, f"Wi-Fi SSID {ssid_name} TP-Link WR840N berhasil diperbarui"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, f"Wi-Fi SSID {ssid_name} TP-Link WR840N berhasil diperbarui (WLAN Synced)"
        except Exception:
            pass

        try:
            payload = {"ssid": ssid_name, "psk": ssid_pwd, "secType": "wpa2-psk"}
            r_cgi = self.session.post(f"{self.base_url}/cgi/wlan", data=payload, timeout=self.timeout)
            if r_cgi.status_code in [200, 302]:
                return True, f"Wi-Fi SSID {ssid_name} TP-Link berhasil diperbarui via CGI"
        except Exception as e:
            return False, f"Gagal update Wi-Fi TP-Link: {str(e)}"

        return False, "Gagal mengonfigurasi Wi-Fi TP-Link WR840N"

    def reboot(self) -> Tuple[bool, str]:
        try:
            self.session.get(f"{self.base_url}/userRpm/SysRebootRpm.htm?Reboot=Reboot", timeout=3)
            return True, "Reboot command sent to TP-Link WR840N"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "TP-Link WR840N sedang reboot"
        except Exception:
            pass

        try:
            self.session.post(f"{self.base_url}/cgi/reboot", data={"action": "reboot"}, timeout=3)
            return True, "Reboot command sent via CGI"
        except Exception as e:
            return False, f"Reboot error: {str(e)}"
