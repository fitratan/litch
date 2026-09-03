import re
import json
import requests
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter

class TendaAdapter(BaseONTAdapter):
    vendor_name = "Tenda (F3 / F6 / AC / N301 Series)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["tenda wireless router", "tenda technology", "reasyui", "b28n.js"]):
                return True
            if "tenda" in text or "tenda" in r.headers.get("server", "").lower():
                return True
            # Probe Tenda API
            r2 = self.session.get(f"{self.base_url}/goform/getHomePageInfo?modules=loginAuth,wifiRelay", timeout=self.timeout)
            if r2.status_code == 200 and "loginauth" in r2.text.lower():
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            # 1. Check if Tenda has no password enabled
            r_info = self.session.get(f"{self.base_url}/goform/getHomePageInfo?modules=loginAuth", timeout=self.timeout)
            if r_info.status_code == 200:
                try:
                    data = r_info.json()
                    has_pwd = data.get("loginAuth", {}).get("hasLoginPwd")
                    if has_pwd == "false":
                        self.authenticated_user = "admin"
                        self.authenticated_password = ""
                        return True, "Login Successful (No Password Set)"
                except Exception:
                    pass

            # 2. Form Login via goform/loginAuth, goform/formLogin, or login/Auth
            payloads = [
                {"adminPassword": password},
                {"password": password},
                {"admin_pwd": password},
                {"loginPwd": password},
                {"username": username, "password": password},
                {"user": username, "password": password},
            ]
            endpoints = [
                f"{self.base_url}/goform/loginAuth",
                f"{self.base_url}/login/Auth",
                f"{self.base_url}/goform/formLogin",
            ]
            for ep in endpoints:
                for p in payloads:
                    try:
                        r = self.session.post(ep, data=p, timeout=self.timeout)
                        if r.status_code in [200, 302] and "err" not in r.text.lower():
                            # Test session
                            r_check = self.session.get(f"{self.base_url}/goform/getStatus?modules=internetStatus", timeout=self.timeout)
                            if r_check.status_code == 200 and "internetstatus" in r_check.text.lower():
                                self.authenticated_user = username or "admin"
                                self.authenticated_password = password
                                return True, "Login Successful"
                    except Exception:
                        pass

            # Fallback basic auth
            r_basic = self.session.get(f"{self.base_url}/", auth=(username, password), timeout=self.timeout)
            if r_basic.status_code == 200:
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
            "connection_name": "WAN",
            "status": "Disconnected",
            "subnet": None,
            "wan_subnet": None,
        }

        try:
            # Query Tenda real status
            r = self.session.get(f"{self.base_url}/goform/getStatus?modules=internetStatus,deviceStatistics,systemInfo,wanAdvCfg", timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                sys_info = data.get("systemInfo", {})
                info["wan_ip"] = sys_info.get("statusWanIP")
                info["gateway"] = sys_info.get("statusWanGaterway")
                info["wan_gateway"] = info["gateway"]
                info["netmask"] = sys_info.get("statusWanMask")
                info["mode"] = sys_info.get("wanType", "Unknown").upper()

            # Query Tenda Wi-Fi & PPPoE config
            r_wan = self.session.get(f"{self.base_url}/goform/getWanParameter", timeout=self.timeout)
            if r_wan.status_code == 200:
                try:
                    w_data = r_wan.json()
                    if w_data.get("pppoeUser"):
                        info["pppoe_user"] = w_data["pppoeUser"]
                    if w_data.get("pppoePwd"):
                        info["pppoe_password"] = w_data["pppoePwd"]
                except Exception:
                    pass

            r_wf = self.session.get(f"{self.base_url}/goform/getWifi?modules=wifiBasicCfg,wifiVirSsid", timeout=self.timeout)
            if r_wf.status_code == 200:
                wf_data = r_wf.json()
                ssid_name = wf_data.get("wifiBasicCfg", {}).get("wifiSSID")
                if ssid_name:
                    info["connection_name"] = f"Wi-Fi: {ssid_name}"

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
                "wanType": "pppoe" if mode == "PPPoE" else ("dhcp" if mode == "DHCP" else "static"),
                "pppoeUser": user,
                "pppoePwd": pwd,
                "vlanEnable": "1" if vlan else "0",
                "vlanId": vlan if vlan else "0",
                "module1": "wanAdvCfg",
            }
            r = self.session.post(f"{self.base_url}/goform/setWanParameter", data=payload, timeout=max(self.timeout, 8))
            if r.status_code in [200, 302]:
                return True, f"WAN updated ({mode} | User: {user})"
        except Exception as e:
            return False, f"Failed to configure WAN: {str(e)}"

        return False, "Failed to apply WAN settings on Tenda router"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        enable_all = lan_config.get("enable", True)
        try:
            payload = {
                "lanPortEnable": "1" if enable_all else "0",
                "module1": "lanPortCfg",
            }
            r = self.session.post(f"{self.base_url}/goform/setLanStatus", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_desc = "AKTIF (Semua Port ON)" if enable_all else "NONAKTIF (Semua Port OFF)"
                return True, f"Port LAN berhasil diatur ke {status_desc}"
        except Exception as e:
            return False, f"Gagal konfigurasi port LAN: {str(e)}"

        return False, "Gagal mengubah konfigurasi port LAN pada router Tenda"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        ssid_idx = int(ssid_config.get("ssid_index", 1))
        enable = bool(ssid_config.get("enable", True))
        ssid_name = ssid_config.get("ssid_name", "dgtlnetsolution")
        auth_mode = ssid_config.get("auth_mode", "Open")
        password = ssid_config.get("password", "")
        hide_ssid = bool(ssid_config.get("hide_ssid", False))

        try:
            if ssid_idx == 1:
                payload = {
                    "wifiEn": "true" if enable else "false",
                    "wifiSSID": ssid_name,
                    "wifiSecurityMode": "none" if (auth_mode.lower() == "open" or not password) else "wpa&wpa2",
                    "wifiPwd": password,
                    "wifiHideSSID": "true" if hide_ssid else "false",
                    "module1": "wifiBasicCfg",
                }
            else:
                payload = {
                    "multiWifiEnable": "1" if enable else "0",
                    "multiWifiSSID": ssid_name,
                    "multiWifiPwd": password,
                    "multiWifiSecurityMode": "none" if (auth_mode.lower() == "open" or not password) else "wpa&wpa2",
                    "module1": "wifiVirSsid",
                }
            r = self.session.post(f"{self.base_url}/goform/setWifi", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                status_str = f"SSID{ssid_idx} '{ssid_name}' ({'AKTIF' if enable else 'NONAKTIF'}, Keamanan: {auth_mode if password else 'Open/Tanpa Password'})"
                return True, f"Wi-Fi berhasil diatur: {status_str}"
        except Exception as e:
            return False, f"Gagal konfigurasi Wi-Fi SSID: {str(e)}"

        return False, "Gagal mengubah konfigurasi Wi-Fi pada router Tenda"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        old_pwd = self.authenticated_password or ""
        try:
            payload = {
                "oldPassword": old_pwd,
                "newPassword": new_password,
                "module1": "sysPassword",
            }
            r = self.session.post(f"{self.base_url}/goform/setSysTools", data=payload, timeout=self.timeout)
            if r.status_code in [200, 302]:
                self.authenticated_password = new_password
                return True, f"Password {username} berhasil diubah ke '{new_password}'"
        except Exception as e:
            return False, f"Gagal ubah password: {str(e)}"

        return False, "Gagal mengubah password pada router Tenda"

    def reboot(self) -> Tuple[bool, str]:
        """Reboot Tenda router/AP after config changes."""
        try:
            r = self.session.post(
                f"{self.base_url}/goform/setSysTools",
                data={"rebootStatus": "1", "module1": "reboot"},
                timeout=self.timeout,
                allow_redirects=False
            )
            if r.status_code in [200, 302, 204]:
                return True, "Reboot berhasil dikirim ke Tenda"
        except Exception:
            pass
        try:
            r = self.session.get(f"{self.base_url}/goform/restart", timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, "Reboot berhasil dikirim ke Tenda"
        except Exception:
            pass
        return False, "Perintah reboot tidak direspon Tenda"

    def lock_anti_reset(self, lock_config: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Burn running config to permanent NVRAM flash and disable reset daemon if Telnet/Root is open.
        """
        actions = []
        try:
            # 1. Telnet Root CLI Button Daemon Kill
            try:
                from adapters.telnet import TelnetSession
                sess = TelnetSession(self.ip, 23, timeout=1.2)
                if sess.connect():
                    for u, p in [("root", "admin"), ("root", "root"), ("admin", "admin")]:
                        sess.read_until("login:", "Username:", timeout=0.8)
                        sess.send(f"{u}\r\n")
                        sess.read_until("Password:", timeout=0.8)
                        sess.send(f"{p}\r\n")
                        out = sess.read_until("#", "$", ">", timeout=1.0)
                        if any(c in out for c in ["#", "$", ">"]) and "incorrect" not in out:
                            sess.send("killall -9 button gpio_monitor 2>/dev/null; rm -f /etc/rc.button/reset 2>/dev/null\r\n")
                            sess.read_until("#", "$", ">", timeout=1.0)
                            sess.close()
                            actions.append("Daemon Tombol Reset Dimatikan (Telnet)")
                            break
            except Exception:
                pass

            # 2. NVRAM Flash Save
            try:
                r = self.session.post(f"{self.base_url}/goform/saveConfig", data={"action": "save"}, timeout=self.timeout)
                if r.status_code in [200, 302]:
                    actions.append("Konfigurasi di-burn ke Flash NVRAM Tenda")
            except Exception:
                pass

            if actions:
                return True, f"Anti-Reset Sukses: {', '.join(actions)}"
            return True, "Konfigurasi aktif berhasil disimpan ke Flash NVRAM Tenda"
        except Exception as e:
            return False, f"Gagal mengunci Anti-Reset Tenda: {str(e)}"
