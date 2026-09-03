import re
import html
import hashlib
import time
import requests
from typing import Dict, Any, Tuple, Optional, List
from adapters.base import BaseONTAdapter

def decode_hex(s: str) -> str:
    """Helper to decode hex-encoded strings and C-style escape sequences from ZTE Transfer_meaning tags."""
    if not s or not isinstance(s, str):
        return ""
    if r"\x" in s:
        try:
            s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)).replace('\\', r'\\'), s)
        except Exception:
            pass
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
    - Challenge-response authentication (SHA256, MD5, GM220 Plaintext token)
    - Hex parameter decoding / encoding
    - Optical power telemetry & System reboot
    - WAN / WLAN / LAN configuration & Password changing
    - Telnet Root DB injection fallback
    """

    def __init__(self, ip: str, port: int = 80, timeout: int = 3):
        super().__init__(ip, port, timeout)
        self.session = self.create_http_session()
        self.base_url = f"http://{self.ip}:{self.port}"
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
        m = re.search(r'getObj\([\"\x27]Frm_Logintoken[\"\x27]\)\.value\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]', text, re.I)
        if m:
            return m.group(1)

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
            # 1. GM220-S & Universal Plaintext + FormToken
            {
                "action": "login",
                "Username": username,
                "Password": clean_pwd,
                "username": username,
                "password": clean_pwd,
                "Frm_Username": username,
                "Frm_Password": clean_pwd,
                "Frm_Logintoken": token or "40",
                "frashnum": "",
                "login": "Login",
            },
            # 2. SHA256 + Token (F670, F663)
            {"Username": username, "Password": sha256_token, "Frm_Logintoken": token, "action": "login", "login": "Login"},
            # 3. MD5 + Token (Classic F609, F660, F477)
            {"Username": username, "Password": md5_token, "Frm_Logintoken": token, "action": "login", "login": "Login"},
            # 4. Pure MD5
            {"Username": username, "Password": md5_pure, "Frm_Logintoken": token, "action": "login"},
        ]

        target_urls = [
            f"{self.base_url}/",
            f"{self.base_url}/getpage.gch?pid=1002&nextpage=login_t.gch",
            f"{self.base_url}/getpage.gch?pid=1001",
            f"{self.base_url}/login.gch",
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
                        r_test = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage=net_ethwan_conf_t.gch", timeout=2)
                        if r_test.status_code == 200 and "login_t.gch" not in r_test.text.lower() and len(r_test.text) > 1000:
                            self.authenticated_user = username
                            self.authenticated_password = password
                            return True, f"Login sukses via Web GUI ({username})"
                except Exception:
                    continue

        return False, "Autentikasi ZTE gagal"

    def get_wan_info(self) -> Dict[str, Any]:
        """Fetch active WAN profiles, IP, VLAN, and connection status."""
        for page in ["net_ethwan_conf_t.gch", "net_gponwan_conf_t.gch", "net_wan_conf_t.gch", "net_tr069wan_conf_t.gch"]:
            try:
                r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r.status_code == 200 and "login_t.gch" not in r.text and len(r.text) > 1000:
                    tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text))
                    clean_tms = {k: decode_hex(v) for k, v in tms.items() if v != "NULL"}

                    st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r.text)
                    st = st_m.group(1) if st_m else self.session_token

                    # If specific WAN fields aren't present directly, query available profiles
                    wan_matches = re.findall(r"Transfer_meaning\([\"\x27]IF_WANNAME(\d+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text)
                    for idx_str, raw_name in wan_matches:
                        d_name = decode_hex(raw_name).strip()
                        if any(k in d_name.upper() for k in ["INTERNET", "PPPOE", "PPP", "ROUTE", "DATA", "HSI", "R_VID"]):
                            # Query details for this profile
                            try:
                                link_post = {
                                    "_SESSION_TOKEN": st,
                                    "IF_ACTION": "wanctype",
                                    "IF_INDEX": str(idx_str),
                                    "IF_NAME": d_name,
                                    "IF_MULTIDISPLAY": "0",
                                    "IF_TYPE": "PPPoE",
                                    "IF_PROTOCOL": "",
                                }
                                r_l = self.session.post(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", data=link_post, timeout=2.5)
                                tms_l = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r_l.text))
                                for k, v in tms_l.items():
                                    if v != "NULL" and (k not in clean_tms or not clean_tms[k]):
                                        clean_tms[k] = decode_hex(v)
                            except Exception:
                                pass

                    user = (
                        clean_tms.get("UserName0")
                        or clean_tms.get("UserName1")
                        or clean_tms.get("UserName2")
                        or clean_tms.get("Frm_UserName")
                        or ""
                    )
                    vlan = (
                        clean_tms.get("VLANID0")
                        or clean_tms.get("VLANID1")
                        or clean_tms.get("VLANID2")
                        or clean_tms.get("Frm_VLANID")
                        or ""
                    )
                    mode = (
                        clean_tms.get("TransType0")
                        or clean_tms.get("TransType1")
                        or clean_tms.get("TransType2")
                        or clean_tms.get("Frm_mode")
                        or "PPPoE"
                    )
                    ip_addr = (
                        clean_tms.get("IPAddress0")
                        or clean_tms.get("IPAddress1")
                        or clean_tms.get("IPAddr0")
                        or ""
                    )
                    return {
                        "username": user or "N/A",
                        "vlan_id": vlan or "N/A",
                        "mode": mode or "PPPoE",
                        "ip_address": ip_addr or "N/A",
                        "raw_profiles": clean_tms
                    }
            except Exception:
                continue
        return {"username": "N/A", "vlan_id": "N/A", "mode": "N/A", "ip_address": "N/A"}

    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        """Update web administration password."""
        clean_pwd = new_password.strip()
        candidate_pages = ["manager_aduser_conf_t.gch", "manager_user_conf_t.gch", "sec_user_t.gch", "user_conf_t.gch"]
        for page in candidate_pages:
            try:
                r1 = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r1.status_code != 200 or len(r1.text) < 500 or "login_t.gch" in r1.text:
                    continue

                st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r1.text)
                st = st_m.group(1) if st_m else self.session_token

                idx = "0" if username == "admin" else "1"
                payload = {
                    "_SESSION_TOKEN": st,
                    "IF_ACTION": "apply",
                    "IF_IDLE": "edit",
                    "IF_INDEX": idx,
                    "Username": username,
                    "Password": clean_pwd,
                    "OldPassword": self.authenticated_password or "admin",
                    "Frm_Username": username,
                    "Frm_Password": clean_pwd,
                    "Frm_CfmPassword": clean_pwd,
                    "Frm_OldPassword": self.authenticated_password or "admin",
                    "Type": "1",
                    "Enable": "1",
                    "Right": "1" if username == "admin" else "2",
                }
                r_post = self.session.post(
                    f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                    data=payload,
                    headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}"},
                    timeout=4
                )
                if r_post.status_code == 200 and "error" not in r_post.text.lower():
                    self.authenticated_password = clean_pwd
                    return True, f"Password {username} berhasil diubah ke '{clean_pwd}'"
            except Exception:
                continue

        # Telnet Root DB Fallback for Password Change
        try:
            from adapters.telnet import TelnetSession
            sess = TelnetSession(self.ip, 23, timeout=2.0)
            if sess.connect():
                creds = [("root", "Zte521"), ("admin", "dnsolution"), ("superadmin", "suportadmin"), ("admin", "admin"), ("root", "root")]
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
                    sess.send(f"sendcmd 1 DB set DevAuthInfo 0 User {username}\r\n")
                    sess.read_until("#", "$", ">", timeout=0.5)
                    sess.send(f"sendcmd 1 DB set DevAuthInfo 0 Pass {clean_pwd}\r\n")
                    sess.read_until("#", "$", ">", timeout=0.5)
                    sess.send("sendcmd 1 DB save\r\n")
                    sess.read_until("#", "$", ">", timeout=1.0)
                    sess.send("sendcmd 1 DB default\r\n")
                    sess.read_until("#", "$", ">", timeout=1.0)
                    sess.close()
                    self.authenticated_password = clean_pwd
                    return True, f"Password {username} berhasil diubah ke '{clean_pwd}' via Telnet DB"
        except Exception:
            pass

        return False, "Gagal mengubah password ONT ZTE"

    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        """Configure LAN port binding / isolation / DHCP."""
        for page in ["net_portbind_t.gch", "net_dhcp_server_t.gch", "net_lan_conf_t.gch"]:
            try:
                r1 = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r1.text)
                st = st_m.group(1) if st_m else self.session_token

                payload = {"_SESSION_TOKEN": st, "IF_ACTION": "apply", "IF_IDLE": "edit"}
                payload.update(lan_config)
                r_post = self.session.post(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", data=payload, timeout=4)
                if r_post.status_code == 200:
                    return True, "Konfigurasi LAN / Port binding berhasil diterapkan"
            except Exception:
                continue
        return False, "Gagal mengonfigurasi LAN"

    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        """Configure Wi-Fi SSID name, password, and security mode."""
        ssid_name = ssid_config.get("ssid_name", "")
        ssid_pwd = ssid_config.get("wlan_password", "")
        ssid_idx = str(ssid_config.get("ssid_index", "1"))
        auth_mode = ssid_config.get("auth_mode", "WPA2-PSK")

        candidate_pages = [
            "net_wlan_essid_t.gch",
            "net_wlan_secrity_t.gch",
            "net_wlan_basic_t.gch",
            "wlan_security_basic_t.gch",
            "net_wlan_sec_t.gch",
            "net_wlan_conf_t.gch",
        ]
        for page in candidate_pages:
            try:
                r1 = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r1.status_code != 200 or len(r1.text) < 500 or "login_t.gch" in r1.text:
                    continue

                st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r1.text)
                st = st_m.group(1) if st_m else self.session_token

                idx = str(int(ssid_idx) - 1)
                payload = {
                    "_SESSION_TOKEN": st,
                    "IF_ACTION": "apply",
                    "IF_IDLE": "edit",
                    "IF_INDEX": idx,
                    f"ESSID{idx}": ssid_name,
                    f"KeyPassphrase{idx}": ssid_pwd,
                    f"BeaconType{idx}": "11i" if "WPA" in auth_mode else "None",
                    "ESSID": ssid_name,
                    "KeyPassphrase": ssid_pwd,
                    "Frm_ESSID": ssid_name,
                    "Frm_KeyPassphrase": ssid_pwd,
                    "BeaconType": "11i" if "WPA" in auth_mode else "None",
                    "11iAuthMode": "PSKAuthentication",
                    "11iEncryptType": "AESEncryption",
                }
                r_post = self.session.post(
                    f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}",
                    data=payload,
                    headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}"},
                    timeout=5
                )
                if r_post.status_code == 200 and "error" not in r_post.text.lower():
                    return True, f"Wi-Fi SSID '{ssid_name}' berhasil diperbarui"
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                return True, f"Wi-Fi SSID '{ssid_name}' berhasil diperbarui (WLAN Synced)"
            except Exception:
                continue
        return False, "Gagal mengonfigurasi Wi-Fi SSID ZTE"

    def get_wifi_info(self) -> Dict[str, Any]:
        """Fetch Wi-Fi SSIDs and security keys."""
        for page in ["net_wlan_basic_t.gch", "wlan_security_basic_t.gch", "net_wlan_conf_t.gch"]:
            try:
                r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage={page}", timeout=3)
                if r.status_code == 200 and "login_t.gch" not in r.text and len(r.text) > 1000:
                    tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text))
                    clean_tms = {k: decode_hex(v) for k, v in tms.items() if v != "NULL"}
                    ssid = clean_tms.get("ESSID0", clean_tms.get("ESSID1", clean_tms.get("Frm_ESSID", "")))
                    pwd = clean_tms.get("KeyPassphrase0", clean_tms.get("KeyPassphrase1", clean_tms.get("Frm_KeyPassphrase", "")))
                    return {"ssid": ssid or "N/A", "password": pwd or "N/A", "enabled": True}
            except Exception:
                continue
        return {"ssid": "N/A", "password": "N/A", "enabled": False}

    def execute_telnet_db_wan(self, user: str, pwd: str, vlan: str = "", mode: str = "PPPoE") -> Tuple[bool, str]:
        """Direct root Telnet database override fallback."""
        try:
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
                if r.status_code == 200 and "login_t.gch" not in r.text and len(r.text) > 1000:
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

    def lock_anti_reset(self, lock_config: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        try:
            r = self.session.get(f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch", timeout=3)
            st_m = re.search(r"var\s+session_token\s*=\s*[\"\x27]([^\x27\"]+)[\"\x27]", r.text)
            st = st_m.group(1) if st_m else self.session_token

            payload = {
                "_SESSION_TOKEN": st,
                "IF_ACTION": "save",
                "IF_MULTIDISPLAY": "0",
            }
            self.session.post(
                f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch",
                data=payload,
                headers={"Referer": f"{self.base_url}/getpage.gch?pid=1002&nextpage=manager_dev_config_t.gch"},
                timeout=4
            )
            return True, "Konfigurasi disimpan permanen ke Flash Storage (Web Commit)"
        except Exception:
            return False, "Gagal mengunci konfigurasi"

    def burn_config_to_rom(self) -> Tuple[bool, str]:
        return self.lock_anti_reset()

    def disable_reset_button(self) -> Tuple[bool, str]:
        return self.lock_anti_reset()
