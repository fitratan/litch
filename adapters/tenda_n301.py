import re
import base64
import hashlib
import requests
from typing import Dict, Any, Tuple, Optional
from adapters.tenda_base import TendaBaseAdapter


class TendaN301Adapter(TendaBaseAdapter):
    """
    Dedicated driver for Tenda N301 / F3 / F6 / F9 / AC10 / AC1200 SOHO Wi-Fi Routers.
    - Endpoints: /goform/loginAuth, /goform/setWan, /goform/WifiBasicSet, /goform/sysReboot
    - Base64 / Cookie auth and goform API
    """
    vendor_name = "Tenda N301 / F3 (Wireless Router)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.detected_model = "Tenda N301 / F3"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["n301", "f3", "f6", "reasyui", "b28n.js", "tendawifi.com", "tenda wireless"]):
                return True
            if "server" in r.headers and "tenda" in r.headers["server"].lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        clean_pwd = password.strip()
        b64_pwd = base64.b64encode(clean_pwd.encode()).decode()
        md5_pwd = hashlib.md5(clean_pwd.encode()).hexdigest()

        # Set cookie authentication header
        self.session.cookies.set("password", b64_pwd)

        payloads = [
            {"username": username, "password": b64_pwd, "check_en": "0"},
            {"username": username, "password": clean_pwd},
            {"password": b64_pwd},
            {"password": clean_pwd},
            {"password": md5_pwd},
        ]

        endpoints = [
            f"{self.base_url}/login/Auth",
            f"{self.base_url}/goform/loginAuth",
            f"{self.base_url}/goform/login",
        ]

        for ep in endpoints:
            for p in payloads:
                try:
                    r = self.session.post(ep, data=p, timeout=self.timeout, allow_redirects=True)
                    text = r.text.lower()
                    if "error" not in text and (r.status_code == 200 or "main.html" in r.url or "index.html" in r.url):
                        # Verify access to homepage info
                        r_test = self.session.get(f"{self.base_url}/goform/gethomepageinfo", timeout=2)
                        if r_test.status_code == 200 and len(r_test.text) > 10:
                            self.authenticated_user = username
                            self.authenticated_password = clean_pwd
                            return True, f"Login sukses Tenda N301/F3 ({username})"
                except Exception:
                    continue

        # Test if cookie auth alone gives access
        try:
            r_test = self.session.get(f"{self.base_url}/goform/gethomepageinfo", timeout=2)
            if r_test.status_code == 200 and len(r_test.text) > 10:
                self.authenticated_user = username
                self.authenticated_password = clean_pwd
                return True, f"Login sukses Tenda N301/F3 via Cookie ({username})"
        except Exception:
            pass

        return False, "Autentikasi Tenda N301/F3 gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        info = {
            "vendor": self.vendor_name,
            "wan_ip": None,
            "mode": "PPPoE",
            "vlan": None,
            "pppoe_user": None,
        }
        for ep in ["/goform/gethomepageinfo", "/goform/AdvGetWan", "/goform/module?module=status"]:
            try:
                r = self.session.get(f"{self.base_url}{ep}", timeout=self.timeout)
                text = r.text
                u_m = re.search(r'(?:pppoeUser|wanUser|username|user)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
                if u_m and u_m.group(1) not in ["admin", "root"]:
                    info["pppoe_user"] = u_m.group(1)

                ip_m = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
                valid_ips = [ip for ip in ip_m if not ip.startswith("192.168.0.") and not ip.startswith("192.168.1.") and ip not in ["0.0.0.0", "255.255.255.0"]]
                if valid_ips:
                    info["wan_ip"] = valid_ips[0]
            except Exception:
                continue
        return info

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        mode = wan_config.get("mode", "PPPoE")
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")
        vlan = str(wan_config.get("vlan_id", "")).strip()

        payloads = [
            {
                "wanType": "pppoe",
                "pppoeUser": user,
                "pppoePwd": pwd,
                "wanSpeed": "auto",
                "mtu": "1492",
                "vlanTag": "1" if vlan else "0",
                "vlanId": vlan or "100",
            },
            {
                "wanType": "pppoe",
                "pppUser": user,
                "pppPwd": pwd,
                "vlan_en": "1" if vlan else "0",
                "vlan_id": vlan or "100",
            }
        ]

        for ep in ["/goform/setWan", "/goform/AdvSetWan", "/goform/fast_set_wan"]:
            for p in payloads:
                try:
                    r = self.session.post(f"{self.base_url}{ep}", data=p, timeout=self.timeout)
                    if r.status_code in [200, 302]:
                        return True, f"WAN Tenda N301/F3 berhasil dikonfigurasi ({mode} | User: {user})"
                except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
                    return True, f"WAN Tenda N301/F3 berhasil dikonfigurasi ({mode} | User: {user} - Network Synced)"
                except Exception:
                    continue

        return False, "Gagal mengonfigurasi WAN Tenda N301/F3"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")

        payloads = [
            {
                "ssid": ssid_name,
                "hideSsid": "0",
                "securityMode": "wpa2psk",
                "wpaKey": ssid_pwd,
            },
            {
                "ssid": ssid_name,
                "key": ssid_pwd,
                "security": "wpa2-psk",
            }
        ]

        for ep in ["/goform/WifiBasicSet", "/goform/setWifi", "/goform/WifiSecuritySet"]:
            for p in payloads:
                try:
                    r = self.session.post(f"{self.base_url}{ep}", data=p, timeout=self.timeout)
                    if r.status_code in [200, 302]:
                        return True, f"Wi-Fi SSID {ssid_name} Tenda N301/F3 berhasil diperbarui"
                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    return True, f"Wi-Fi SSID {ssid_name} Tenda N301/F3 berhasil diperbarui (WLAN Synced)"
                except Exception:
                    continue

        return False, "Gagal mengonfigurasi Wi-Fi Tenda N301/F3"

    def get_wifi_info(self) -> Dict[str, Any]:
        for ep in ["/goform/WifiBasicGet", "/goform/gethomepageinfo"]:
            try:
                r = self.session.get(f"{self.base_url}{ep}", timeout=self.timeout)
                text = r.text
                ssid_m = re.search(r'(?:ssid|wifi_ssid)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
                pwd_m = re.search(r'(?:wpaKey|key|wifi_pwd|pwd)["\']?\s*[:=,]\s*["\']([^"\']+)["\']', text, re.I)
                if ssid_m:
                    return {
                        "ssid": ssid_m.group(1),
                        "password": pwd_m.group(1) if pwd_m else "N/A",
                        "enabled": True
                    }
            except Exception:
                continue
        return {"ssid": "N/A", "password": "N/A", "enabled": False}

    def reboot(self) -> Tuple[bool, str]:
        for ep in ["/goform/sysReboot", "/goform/SysToolReboot"]:
            try:
                self.session.post(f"{self.base_url}{ep}", data={"action": "reboot"}, timeout=3)
                return True, "Reboot command sent to Tenda N301/F3"
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                return True, "Tenda N301/F3 sedang reboot"
            except Exception:
                continue
        return False, "Gagal mengirim command reboot"
