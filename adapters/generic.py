import requests
from typing import Dict, Any, Tuple
from adapters.base import BaseONTAdapter

class GenericAdapter(BaseONTAdapter):
    vendor_name = "Generic / XPON ONT"

    def __init__(self, ip: str, port: int = 80, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"

    def detect(self) -> bool:
        # Fallback adapter, always returns True if port is open
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout)
            return r.status_code < 500
        except Exception:
            return False

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        eff_user = username if username else "admin"
        try:
            # 1. Probe root / and HTTP Basic Auth
            r = self.session.get(f"{self.base_url}/", auth=(eff_user, password), timeout=self.timeout)
            if r.status_code == 200 and "login" not in r.text.lower() and "unauthorized" not in r.text.lower():
                self.authenticated_user = eff_user
                self.authenticated_password = password
                return True, "Login Successful (Basic Auth)"

            # Check if this is a web server without any login form (e.g. Nginx, OpenResty, Apache 404)
            has_form_or_input = any(k in r.text.lower() for k in ["<form", "<input", "password", "username", "login"])
            if not has_form_or_input and "www-authenticate" not in r.headers:
                return False, "No web login form detected"

            # 2. Extract form action from HTML if present
            target_path = "/login.cgi"
            import re
            m = re.search(r'<form[^>]*action=[\"\x27]([^\x27\"]+)[\"\x27]', r.text, re.I)
            if m and m.group(1):
                action = m.group(1).strip()
                target_path = action if action.startswith("/") else f"/{action}"

            login_paths = [target_path]
            for p in ["/goform/login", "/cgi-bin/login.cgi", "/login.cgi"]:
                if p not in login_paths:
                    login_paths.append(p)

            payloads = [
                {"username": eff_user, "password": password},
                {"user": eff_user, "password": password},
                {"password": password},
            ]

            for path in login_paths[:2]:
                for p_data in payloads:
                    try:
                        r2 = self.session.post(f"{self.base_url}{path}", data=p_data, timeout=self.timeout)
                        if r2.status_code in [200, 302]:
                            text_l = r2.text.lower()
                            if not any(err in text_l for err in ["fail", "error", "invalid", "wrong", "gagal", "incorrect", "denied"]):
                                if "session" in r2.headers.get("Set-Cookie", "").lower() or "auth" in r2.headers.get("Set-Cookie", "").lower() or r2.status_code == 302:
                                    self.authenticated_user = eff_user
                                    self.authenticated_password = password
                                    return True, "Login Successful"
                    except Exception:
                        pass
        except Exception as e:
            return False, f"Error: {str(e)}"
        
        return False, "Login failed"

    def get_wan_info(self) -> Dict[str, Any]:
        return {"vendor": self.vendor_name, "mode": "Unknown", "vlan": None, "pppoe_user": None}

    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        return False, "Generic automatic WAN setup not supported. Use TR-069 or vendor adapter."
