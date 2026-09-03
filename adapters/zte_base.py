import re
import html
import hashlib
import time
import requests
from typing import Dict, Any, Tuple, Optional, List
from adapters.base import BaseONTAdapter

def decode_hex(s: str) -> str:
    """Helper to decode hex-encoded strings from ZTE Transfer_meaning tags."""
    if not s or not isinstance(s, str):
        return ""
    if s.startswith("&#x") or s.startswith("&amp;#x"):
        clean = s.replace("&amp;#x", "").replace("&#x", "").rstrip(";")
        try:
            return bytes.fromhex(clean).decode("utf-8", errors="ignore")
        except Exception:
            return s
    if len(s) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", s) and len(s) >= 4:
        try:
            decoded = bytes.fromhex(s).decode("utf-8", errors="ignore")
            if all(c.isprintable() or c.isspace() for c in decoded) and len(decoded) > 0:
                return decoded
        except Exception:
            pass
    return s


class ZTEBaseAdapter(BaseONTAdapter):
    """
    Base ZTE ONT Adapter providing shared infrastructure:
    - Session management & Token extraction
    - Challenge-response authentication (SHA256, MD5, Plaintext)
    - Hex parameter decoding / encoding
    - Optical power telemetry & System reboot
    - Telnet Root DB injection fallback
    """

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session_token = ""
        self.detected_model = ""

    def detect(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/", timeout=self.timeout)
            text_l = r.text.lower()
            return (
                "getpage.gch" in r.url.lower()
                or "frm_logintoken" in text_l
                or "zfc_" in text_l
                or "mini web server" in str(r.headers.get("Server", "")).lower()
                or any(k in text_l for k in ["zte", "zxic", "gm220", "f609", "f670", "f660", "f663", "f477"])
            )
        except Exception:
            return False

    def _extract_token_from_html(self, text: str) -> str:
        if not text:
            return ""
        m = re.search(r'id=["\x27]Frm_Logintoken["\x27]\s+value=["\x27]([^"\x27]+)["\x27]', text, re.I)
        if not m:
            m = re.search(r'name=["\x27]Frm_Logintoken["\x27]\s+value=["\x27]([^"\x27]+)["\x27]', text, re.I)
        if m:
            return m.group(1)

        m = re.search(r'Transfer_meaning\([\"\x27]login_token[\"\x27]\s*,\s*[\"\x27]([^\x27\"]+)[\"\x27]\)', text)
        if m:
            return decode_hex(m.group(1))

        m = re.search(r'var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]', text)
        if m:
            return m.group(1)

        return ""

    def get_login_token(self, force_refresh: bool = False) -> str:
        if self.session_token and not force_refresh:
            return self.session_token

        for candidate_url in [
            f"{self.base_url}/",
            f"{self.base_url}/getpage.gch?pid=1002&nextpage=login_t.gch",
            f"{self.base_url}/getpage.gch?pid=1001",
        ]:
            try:
                r = self.session.get(candidate_url, timeout=self.timeout)
                tok = self._extract_token_from_html(r.text)
                if tok:
                    self.session_token = tok
                    return tok
            except Exception:
                continue
        return ""

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Unified challenge-response login across ZTE firmware."""
        self.session_token = ""
        token = self.get_login_token(force_refresh=True)

        clean_pwd = password.strip()
        md5_pure = hashlib.md5(clean_pwd.encode("utf-8")).hexdigest()
        md5_token = hashlib.md5((clean_pwd + token).encode("utf-8")).hexdigest() if token else md5_pure
        sha256_token = hashlib.sha256((clean_pwd + token).encode("utf-8")).hexdigest() if token else clean_pwd

        payloads = [
            {"Username": username, "Password": sha256_token, "Frm_Logintoken": token, "action": "login", "login": "Login"},
            {"Username": username, "Password": md5_token, "Frm_Logintoken": token, "action": "login", "login": "Login"},
            {"Username": username, "Password": md5_pure, "Frm_Logintoken": token, "action": "login"},
            {"Username": username, "Password": clean_pwd, "Frm_Logintoken": token, "action": "login"},
        ]

        target_urls = [
            f"{self.base_url}/getpage.gch?pid=1002&nextpage=login_t.gch",
            f"{self.base_url}/getpage.gch?pid=1001",
            f"{self.base_url}/login.gch",
            f"{self.base_url}/",
        ]

        for post_url in target_urls:
            for p in payloads:
                try:
                    r = self.session.post(
                        post_url,
                        data=p,
                        headers={"Referer": f"{self.base_url}/"},
                        timeout=max(self.timeout, 4),
                        allow_redirects=True,
                    )
                    res_text = r.text.lower()

                    if any(k in res_text for k in ["logout", "main.gch", "status_t.gch", "top.gch", "menu.gch", "net_wan_conf_t.gch", "net_gponwan_conf_t.gch", "net_ethwan_conf_t.gch"]):
                        self.authenticated_user = username
                        self.authenticated_password = password
                        return True, f"Login sukses via Web GUI ({username})"

                    if r.status_code == 200 and "login_t.gch" not in res_text and len(r.text) > 300:
                        r_test = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage=status_t.gch", timeout=2)
                        if r_test.status_code == 200 and "login_t.gch" not in r_test.text.lower():
                            self.authenticated_user = username
                            self.authenticated_password = password
                            return True, f"Login sukses via Web GUI ({username})"
                except Exception:
                    continue

        return False, "Autentikasi ZTE gagal"

    def execute_telnet_db_wan(self, user: str, pwd: str, vlan: str = "", mode: str = "PPPoE") -> Tuple[bool, str]:
        """Direct root Telnet database override fallback."""
        try:
            # Try unlocking telnet if closed
            try:
                self.session.get(f"{self.base_url}/middle_factorymode_t.gch", timeout=1.5)
                self.session.get(f"{self.base_url}/hidden_version_switch.gch", timeout=1.5)
            except Exception:
                pass

            from adapters.telnet import TelnetSession
            sess = TelnetSession(self.ip, 23, timeout=2.0)
            if sess.connect():
                creds = [
                    ("root", "Zte521"),
                    ("admin", "dnsolution"),
                    ("superadmin", "suportadmin"),
                    ("admin", "telkomdso123"),
                    ("admin", "admin"),
                    ("root", "root"),
                    ("root", "adminHW"),
                    ("telecomadmin", "admintelecom"),
                    ("user", "user"),
                ]
                logged_in = False
                for u, p in creds:
                    sess.read_until("login:", "Username:", timeout=0.8)
                    sess.send(f"{u}\r\n")
                    sess.read_until("Password:", timeout=0.8)
                    sess.send(f"{p}\r\n")
                    out = sess.read_until("#", "$", ">", "incorrect", timeout=1.0)
                    if any(c in out for c in ["#", "$", ">"]) and "incorrect" not in out:
                        logged_in = True
                        break

                if logged_in:
                    for inst in ["0", "1", "2"]:
                        sess.send(f"sendcmd 1 DB set WANPPP {inst} Username {user}\r\n")
                        sess.read_until("#", "$", ">", timeout=0.5)
                        sess.send(f"sendcmd 1 DB set WANPPP {inst} Password {pwd}\r\n")
                        sess.read_until("#", "$", ">", timeout=0.5)
                        sess.send(f"sendcmd 1 DB set WANPPP {inst} Enable 1\r\n")
                        sess.read_until("#", "$", ">", timeout=0.5)
                        if vlan and str(vlan).strip():
                            sess.send(f"sendcmd 1 DB set WANCPN {inst} VLANID {str(vlan).strip()}\r\n")
                            sess.read_until("#", "$", ">", timeout=0.5)
                    sess.send("sendcmd 1 DB save\r\n")
                    sess.read_until("#", "$", ">", timeout=1.0)
                    sess.send("sendcmd 1 DB default\r\n")
                    sess.read_until("#", "$", ">", timeout=1.0)
                    sess.close()
                    return True, f"WAN PPPoE updated via Telnet DB Bypass ({mode} | VLAN {vlan or 'Bawaan'} | User: {user})"
        except Exception:
            pass
        return False, "Telnet DB override failed"

    def reboot(self) -> Tuple[bool, str]:
        """Send reboot signal via Web GUI or Telnet."""
        try:
            r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_conf_t.gch", timeout=3)
            st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r.text)
            st = st_m.group(1) if st_m else self.session_token

            payload = {
                "_SESSION_TOKEN": st,
                "IF_ACTION": "reboot",
                "IF_MULTIDISPLAY": "0",
            }
            self.session.post(
                f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_conf_t.gch",
                data=payload,
                headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_conf_t.gch"},
                timeout=4
            )
            return True, "Reboot command sent to ONT"
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return True, "Reboot command accepted (Device restarting)"
        except Exception as e:
            return False, f"Reboot error: {e}"

    def get_optical_power(self) -> Dict[str, Any]:
        """Fetch optical RX/TX power and PON status."""
        for page in ["pon_status_t.gch", "pon_optical_info_t.gch", "net_gpon_status_t.gch", "status_pon_info_t.gch"]:
            try:
                r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r.status_code == 200 and "login_t.gch" not in r.text:
                    tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text))
                    rx = decode_hex(tms.get("RxPower", tms.get("rx_power", "")))
                    tx = decode_hex(tms.get("TxPower", tms.get("tx_power", "")))
                    temp = decode_hex(tms.get("Temperature", tms.get("temperature", "")))
                    return {
                        "rx_power_dbm": rx or "N/A",
                        "tx_power_dbm": tx or "N/A",
                        "temperature": temp or "N/A",
                        "status": "Online" if rx else "Unknown"
                    }
            except Exception:
                continue
        return {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "temperature": "N/A", "status": "N/A"}
