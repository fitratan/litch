import re
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter
from adapters.vsol import VSOLAdapter

class RealtekBoAAdapter(VSOLAdapter):
    """
    Dedicated Driver for Realtek BoA Web Server (Boa/0.94) based ONUs:
    - VSOL (V2801SG, V2804, XPON)
    - C-Data (FD511, FD504)
    - Syrotech, Netlink, Optima, BDCOM, OEM XPON/EPON Generic
    """
    vendor_name = "Realtek BoA OEM (VSOL/C-Data/XPON)"

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout, allow_redirects=True)
            text = r.text.lower()
            if any(k in text for k in ["boaform", "vsol", "c-data", "cdata", "v2801", "v2802", "fd511", "xpon onu", "epon onu", "gpon onu", "syrotech", "netlink"]):
                return True
            if "server" in r.headers and any(s in r.headers["server"].lower() for s in ["boa", "vsol", "c-data", "realtek"]):
                return True
        except Exception:
            pass
        return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        # Form endpoints specifically targeting BoA architecture
        endpoints = [
            (f"{self.base_url}/boaform/admin/formLogin", {
                "username": username,
                "psd": password,
                "save": "Login",
                "submit-url": "/admin/login.asp"
            }),
            (f"{self.base_url}/boaform/admin/formLogin", {
                "username": username,
                "password": password,
                "submit": "Login"
            }),
            (f"{self.base_url}/goform/formLogin", {
                "username": username,
                "password": password,
                "submit": "Login"
            }),
        ]

        for url, payload in endpoints:
            try:
                r = self.session.post(url, data=payload, timeout=self.timeout, allow_redirects=True)
                if any(err in r.text.lower() for err in ["login_failed", "invalid user", "password error", "error_pwd"]):
                    continue

                for check_url in [f"{self.base_url}/admin/status.asp", f"{self.base_url}/status_device.asp", f"{self.base_url}/status.asp", f"{self.base_url}/home.asp"]:
                    try:
                        r_check = self.session.get(check_url, timeout=self.timeout)
                        if r_check.status_code == 200 and "login" not in r_check.url.lower() and len(r_check.text) > 300:
                            self.authenticated_user = username
                            self.authenticated_password = password
                            return True, "Login Successful (BoA Form POST)"
                    except Exception:
                        pass

                if r.status_code in [200, 302] and "login" not in r.url.lower():
                    self.authenticated_user = username
                    self.authenticated_password = password
                    return True, "Login Successful"
            except Exception:
                pass

        # Multi-Protocol Fallback: HTTP Basic Auth
        try:
            r_basic = self.session.get(f"{self.base_url}/", auth=(username, password), timeout=self.timeout)
            if r_basic.status_code == 200 and len(r_basic.text) > 200:
                self.authenticated_user = username
                self.authenticated_password = password
                return True, "Login Successful (Basic Auth)"
        except Exception:
            pass

        return False, "Login failed on Realtek BoA device"
