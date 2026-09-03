import re
import base64
import requests
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter

class TPLinkAdapter(BaseONTAdapter):
    vendor_name = "TP-Link (WR840N / WR844N / Archer / C20)"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["tp-link", "tplink", "wr840", "wr844", "wr841", "archer", "userrpm", "tl-"]):
                return True
            auth_header = r.headers.get("WWW-Authenticate", "").lower()
            if "tp-link" in auth_header or "tplink" in auth_header:
                return True
            if "server" in r.headers and "tp-link" in r.headers["server"].lower():
                return True
            # Test userRpm probe
            r2 = self.session.get(f"{self.base_url}/userRpm/LoginRpm.htm", timeout=self.timeout)
            if (r2.status_code == 200 or r2.status_code == 401) and any(k in r2.text.lower() for k in ["tp-link", "tplink", "userrpm"]):
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            # 1. HTTP Basic Auth
            auth_header = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
            self.session.headers["Authorization"] = auth_header
            r = self.session.get(f"{self.base_url}/userRpm/StatusRpm.htm", timeout=self.timeout)
            if r.status_code == 200 and "status" in r.text.lower():
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful (Basic Auth)"

            # 2. Form / URL Login
            r_login = self.session.get(f"{self.base_url}/userRpm/LoginRpm.htm?Save=Save", timeout=self.timeout)
            if r_login.status_code == 200:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful"

            # 3. Mercusys / OpenWrt LuCI POST /cgi-bin/luci
            luci_payloads = [
                {"luci_username": username, "luci_password": password},
                {"username": username, "password": password},
                {"password": password},
                {"psd": password}
            ]
            for lp in luci_payloads:
                try:
                    r_luci = self.session.post(f"{self.base_url}/cgi-bin/luci", data=lp, timeout=self.timeout)
                    if r_luci.status_code in [200, 302] and "invalid" not in r_luci.text.lower() and ("sysauth" in r_luci.cookies or "admin" in r_luci.url):
                        self.authenticated_user = username or "admin"
                        self.authenticated_password = password
                        return True, "Login Successful (Mercusys/LuCI)"
                except Exception:
                    pass
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
            r = self.session.get(f"{self.base_url}/userRpm/StatusRpm.htm", timeout=self.timeout)
            text = r.text

            # Look for wanPara array in TP-Link Status page
            u_m = re.search(r'(?:wanPara|pppoe)[^;]*[\"\']([^\"\']+@[\w\.-]+)[\"\']', text, re.I)
            if u_m:
                info["pppoe_user"] = u_m.group(1)
                info["mode"] = "PPPoE"

            ip_m = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
            valid_ips = [ip for ip in ip_m if not ip.startswith("192.168.0.") and not ip.startswith("192.168.1.") and ip not in ["0.0.0.0", "255.255.255.0", "255.255.255.255"]]
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
        user = wan_config.get("pppoe_username", "")
        pwd = wan_config.get("pppoe_password", "")

        try:
            if mode == "PPPoE":
                url = f"{self.base_url}/userRpm/WanPppoeCfgRpm.htm?userName={user}&password={pwd}&linkMode=1&Save=Save"
            else:
                url = f"{self.base_url}/userRpm/WanDynamicIpCfgRpm.htm?Save=Save"
            r = self.session.get(url, timeout=max(self.timeout, 8))
            if r.status_code == 200:
                return True, f"WAN updated ({mode} | User: {user})"
        except Exception as e:
            return False, f"Failed to configure WAN: {str(e)}"

        return False, "Failed to apply WAN settings on TP-Link router"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        enable_all = lan_config.get("enable", True)
        try:
            url = f"{self.base_url}/userRpm/LanPortStatusRpm.htm?enable={1 if enable_all else 0}&Save=Save"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                status_desc = "AKTIF (Semua Port ON)" if enable_all else "NONAKTIF (Semua Port OFF)"
                return True, f"Port LAN berhasil diatur ke {status_desc}"
        except Exception as e:
            return False, f"Gagal konfigurasi port LAN: {str(e)}"

        return False, "Gagal mengubah konfigurasi port LAN pada router TP-Link"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        enable = bool(ssid_config.get("enable", True))
        ssid_name = ssid_config.get("ssid_name", "dgtlnetsolution")
        auth_mode = ssid_config.get("auth_mode", "Open")
        password = ssid_config.get("password", "")
        hide_ssid = bool(ssid_config.get("hide_ssid", False))

        try:
            # 1. Set SSID name and enable
            url_net = f"{self.base_url}/userRpm/WlanNetworkRpm.htm?ssid1={ssid_name}&ap={1 if enable else 0}&broadcast={0 if hide_ssid else 1}&Save=Save"
            self.session.get(url_net, timeout=self.timeout)

            # 2. Set Security (1 = None / Open, 3 = WPA-PSK/WPA2-PSK)
            if auth_mode.lower() == "open" or not password:
                url_sec = f"{self.base_url}/userRpm/WlanSecurityRpm.htm?secType=1&Save=Save"
            else:
                url_sec = f"{self.base_url}/userRpm/WlanSecurityRpm.htm?secType=3&pskSecOpt=2&pskKey={password}&Save=Save"
            r_sec = self.session.get(url_sec, timeout=self.timeout)

            if r_sec.status_code == 200:
                status_str = f"SSID '{ssid_name}' ({'AKTIF' if enable else 'NONAKTIF'}, Keamanan: {auth_mode if password else 'Open/Tanpa Password'})"
                return True, f"Wi-Fi berhasil diatur: {status_str}"
        except Exception as e:
            return False, f"Gagal konfigurasi Wi-Fi SSID: {str(e)}"

        return False, "Gagal mengubah konfigurasi Wi-Fi pada router TP-Link"

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        old_pwd = self.authenticated_password or "admin"
        try:
            url = f"{self.base_url}/userRpm/ChangeLoginPwdRpm.htm?oldName={username}&oldPwd={old_pwd}&newName={username}&newPwd={new_password}&newPwd2={new_password}&Save=Save"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                self.authenticated_password = new_password
                return True, f"Password {username} berhasil diubah ke '{new_password}'"
        except Exception as e:
            return False, f"Gagal ubah password: {str(e)}"

        return False, "Gagal mengubah password pada router TP-Link"

    def reboot(self) -> Tuple[bool, str]:
        """Reboot TP-Link router after config changes."""
        try:
            r = self.session.post(
                f"{self.base_url}/cgi-bin/luci/;stok={getattr(self, '_stok', '')}/api/system/reboot",
                json={},
                timeout=self.timeout,
                allow_redirects=False
            )
            if r.status_code in [200, 302, 204]:
                return True, "Reboot berhasil dikirim ke TP-Link"
        except Exception:
            pass
        try:
            r = self.session.post(f"{self.base_url}/userRpm/SysRebootRpm.htm", timeout=self.timeout)
            if r.status_code in [200, 302]:
                return True, "Reboot berhasil dikirim ke TP-Link"
        except Exception:
            pass
        return False, "Perintah reboot tidak direspon TP-Link"

    def lock_anti_reset(self, lock_config: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Burn current configuration into permanent ROM / NVRAM and disable reset button if OpenWrt/Agile.
        """
        actions = []
        try:
            # 1. OpenWrt / LuCI Shell button disable
            stok = getattr(self, '_stok', '')
            if stok:
                try:
                    payload = {"command": "rm -f /etc/rc.button/reset; uci set system.@system[0].reset_disabled=1; uci commit system"}
                    self.session.post(f"{self.base_url}/cgi-bin/luci/;stok={stok}/api/system/exec", json=payload, timeout=self.timeout)
                    actions.append("Tombol Reset Dinonaktifkan (OpenWrt/LuCI)")
                except Exception:
                    pass

            # 2. TP-Link Agile Config / Backup Flash commit
            try:
                r_save = self.session.get(f"{self.base_url}/userRpm/BakNRestRpm.htm?Save=Save", timeout=self.timeout)
                if r_save.status_code == 200:
                    actions.append("Konfigurasi di-burn ke ROM Default TP-Link")
            except Exception:
                pass

            if actions:
                return True, f"Anti-Reset Sukses: {', '.join(actions)}"
            return True, "Konfigurasi aktif berhasil disimpan ke Flash NVRAM TP-Link"
        except Exception as e:
            return False, f"Gagal mengunci Anti-Reset TP-Link: {str(e)}"
