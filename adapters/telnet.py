import socket
import time
import re
from typing import Dict, Any, Optional, Tuple
from adapters.base import BaseONTAdapter


# ---------------------------------------------------------------------------
# Telnet IAC negotiation helper
# ---------------------------------------------------------------------------
IAC  = bytes([255])
DONT = bytes([254])
DO   = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB   = bytes([250])
SE   = bytes([240])

def strip_telnet_negotiation(data: bytes) -> bytes:
    """Strip IAC negotiation bytes from Telnet stream."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i:i+1] == IAC:
            cmd = data[i+1:i+2]
            if cmd in (DO, DONT, WILL, WONT):
                i += 3
            elif cmd == SB:
                end = data.find(bytes(IAC + SE), i+2)
                i = end + 2 if end != -1 else len(data)
            elif cmd == IAC:
                out.append(255)
                i += 2
            else:
                i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


class TelnetSession:
    """
    Raw socket Telnet session with IAC negotiation handling.
    Works on Python 3.11+ (telnetlib deprecated) and earlier.
    """

    def __init__(self, ip: str, port: int = 23, timeout: float = 4.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.ip, self.port))
            # Respond to IAC negotiations immediately so device stops sending them
            time.sleep(0.3)
            self._negotiate()
            return True
        except Exception:
            return False

    def _negotiate(self):
        """Read initial IAC bytes and reply WONT/DONT to everything."""
        try:
            self._sock.settimeout(0.5)
            raw = self._sock.recv(1024)
            reply = bytearray()
            i = 0
            while i < len(raw):
                if raw[i:i+1] == IAC and i + 2 < len(raw):
                    cmd = raw[i+1:i+2]
                    opt = raw[i+2:i+3]
                    if cmd == DO:
                        reply += IAC + WONT + opt
                    elif cmd == WILL:
                        reply += IAC + DONT + opt
                    i += 3
                else:
                    i += 1
            if reply:
                self._sock.sendall(bytes(reply))
        except Exception:
            pass
        finally:
            self._sock.settimeout(self.timeout)

    def read_until(self, *prompts: str, timeout: float = 3.0) -> str:
        """Read data until one of the prompt strings appears."""
        buf = b""
        self._sock.settimeout(0.2)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self._sock.recv(512)
                if chunk:
                    buf += chunk
                    clean = strip_telnet_negotiation(buf).decode("utf-8", errors="replace")
                    for p in prompts:
                        if p.lower() in clean.lower():
                            return clean
            except socket.timeout:
                pass
            except Exception:
                break
        return strip_telnet_negotiation(buf).decode("utf-8", errors="replace")

    def write(self, data: str):
        """Send a line of text followed by CRLF."""
        try:
            self._sock.sendall((data + "\r\n").encode())
        except Exception:
            pass

    def close(self):
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Vendor detection from Telnet banner
# ---------------------------------------------------------------------------
BANNER_VENDOR_MAP = [
    # (keyword_list, vendor_label, shell_type)
    (["zte", "f609", "f612", "f660", "f668", "gm220", "zxhn", "frm_logintoken"],
     "ZTE XPON (Telnet)", "zte"),
    (["huawei", "hg8", "echolife", "hg234", "hg255"],
     "Huawei ONT (Telnet)", "linux"),
    (["fiberhome", "an5506", "an5516", "an5520"],
     "Fiberhome ONT (Telnet)", "linux"),
    (["vsol", "v1600", "v2801"],
     "VSOL ONT (Telnet)", "linux"),
    (["tenda", "tendacn"],
     "Tenda Router (Telnet)", "linux"),
    (["tp-link", "tplink", "archer", "tl-wr"],
     "TP-Link Router (Telnet)", "linux"),
    (["mikrotik", "routeros"],
     "MikroTik RouterOS (Telnet)", "mikrotik"),
    (["busybox", "openwrt", "ddwrt"],
     "Generic Linux/OpenWRT (Telnet)", "linux"),
    (["broadcom", "dsl-", "adsl"],
     "Broadcom DSL Router (Telnet)", "linux"),
]

# Login prompt patterns
LOGIN_PROMPTS  = ["login:", "username:", "login: ", "user: "]
PASSWD_PROMPTS = ["password:", "passwd:", "password: "]
SHELL_PROMPTS  = ["# ", "$ ", "> ", "~ #", "~$ ", "/ #", "/ $", "%"]


def detect_vendor_from_banner(banner: str) -> Tuple[str, str]:
    """
    Returns (vendor_label, shell_type) from Telnet banner text.
    shell_type: 'linux' | 'zte' | 'mikrotik' | 'unknown'
    """
    lower = banner.lower()
    for keywords, label, stype in BANNER_VENDOR_MAP:
        if any(k in lower for k in keywords):
            return label, stype
    if any(p in lower for p in LOGIN_PROMPTS + SHELL_PROMPTS):
        return "Unknown Router (Telnet)", "linux"
    return "Unknown (Telnet)", "unknown"


# ---------------------------------------------------------------------------
# WAN info extraction from shell output
# ---------------------------------------------------------------------------
def _extract_pppoe_from_output(output: str) -> Dict[str, Any]:
    """Parse ifconfig / pppd output to find WAN IP and PPPoE info."""
    info: Dict[str, Any] = {
        "wan_ip": None,
        "gateway": None,
        "pppoe_user": None,
        "mode": "Unknown",
        "connection_name": None,
    }

    # PPP interface IP
    ppp_match = re.search(
        r"ppp\w+\s+.*?(?:inet addr:|inet\s+)(\d+\.\d+\.\d+\.\d+)",
        output, re.IGNORECASE | re.DOTALL
    )
    if ppp_match:
        info["wan_ip"] = ppp_match.group(1)
        info["mode"] = "PPPoE"

    # pppd process args → username
    user_match = re.search(r"user\s+([^\s]+)", output, re.IGNORECASE)
    if user_match:
        info["pppoe_user"] = user_match.group(1)

    # cat /etc/ppp/peers/* output
    peer_user = re.search(r"^user\s+[\"']?([^\s\"']+)", output, re.MULTILINE | re.IGNORECASE)
    if peer_user and not info["pppoe_user"]:
        info["pppoe_user"] = peer_user.group(1)

    # Default route / gateway
    gw_match = re.search(r"default.*?(\d+\.\d+\.\d+\.\d+)", output, re.IGNORECASE)
    if gw_match:
        info["gateway"] = gw_match.group(1)

    # DHCP WAN IP (eth/br interface, non-ppp)
    if not info["wan_ip"]:
        wan_match = re.search(
            r"(?:eth\d|wan\d|br-wan)\s+.*?inet\s+(\d+\.\d+\.\d+\.\d+)",
            output, re.IGNORECASE | re.DOTALL
        )
        if wan_match:
            info["wan_ip"] = wan_match.group(1)
            info["mode"] = "DHCP"

    return info


# ---------------------------------------------------------------------------
# TelnetAdapter — BaseONTAdapter-compatible
# ---------------------------------------------------------------------------
class TelnetAdapter(BaseONTAdapter):
    """
    Fallback adapter for devices with Telnet (port 23) but no HTTP management.
    Supports Linux/BusyBox shell, ZTE CLI, and MikroTik RouterOS CLI.
    """
    vendor_name = "Unknown (Telnet Fallback)"

    def __init__(self, ip: str, port: int = 23, timeout: int = 2):
        super().__init__(ip, port, timeout)
        self._session: Optional[TelnetSession] = None
        self._shell_type: str = "unknown"
        self._banner: str = ""
        self._shell_ready: bool = False

    # ------------------------------------------------------------------
    def detect(self) -> bool:
        try:
            sess = TelnetSession(self.ip, self.port, timeout=2.5)
            if not sess.connect():
                return False
            banner = sess.read_until(*LOGIN_PROMPTS, *SHELL_PROMPTS, timeout=2.5)
            sess.close()
            if banner.strip():
                self._banner = banner
                label, stype = detect_vendor_from_banner(banner)
                self.vendor_name = label
                self._shell_type = stype
                return True
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            sess = TelnetSession(self.ip, self.port, timeout=self.timeout)
            if not sess.connect():
                return False, "Koneksi Telnet gagal"

            banner = sess.read_until(*LOGIN_PROMPTS, *SHELL_PROMPTS, timeout=3.0)

            if not self._banner:
                self._banner = banner
                label, stype = detect_vendor_from_banner(banner)
                self.vendor_name = label
                self._shell_type = stype

            # If already at shell prompt (no auth)
            if any(p in banner for p in SHELL_PROMPTS):
                self._session = sess
                self._shell_ready = True
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Shell terbuka tanpa autentikasi ({self.vendor_name})"

            # Send username
            sess.write(username)
            after_user = sess.read_until(*PASSWD_PROMPTS, *SHELL_PROMPTS, timeout=3.0)

            # If shell appeared after username only
            if any(p in after_user for p in SHELL_PROMPTS):
                self._session = sess
                self._shell_ready = True
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login berhasil (tanpa password) ke {self.vendor_name}"

            # Send password
            sess.write(password)
            after_pass = sess.read_until(*SHELL_PROMPTS, "incorrect", "failed",
                                         "invalid", "login:", timeout=4.0)

            lower = after_pass.lower()
            if any(fail in lower for fail in ["incorrect", "failed", "invalid", "bad password", "login:"]):
                sess.close()
                return False, f"Kredensial salah: {username}:{password}"

            if any(p in after_pass for p in SHELL_PROMPTS):
                self._session = sess
                self._shell_ready = True
                self.authenticated_user = username
                self.authenticated_password = password
                return True, f"Login Telnet berhasil: {username} ke {self.vendor_name}"

            sess.close()
            return False, "Login tidak terkonfirmasi (prompt shell tidak muncul)"

        except Exception as e:
            return False, f"Error Telnet: {str(e)}"

    # ------------------------------------------------------------------
    def _run_cmd(self, cmd: str, wait: float = 1.5) -> str:
        if not self._session or not self._shell_ready:
            return ""
        self._session.write(cmd)
        return self._session.read_until(*SHELL_PROMPTS, timeout=wait)

    # ------------------------------------------------------------------
    def get_wan_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "wan_ip": None, "gateway": None, "netmask": None,
            "mode": "Unknown", "pppoe_user": None,
            "connection_name": None, "vendor": self.vendor_name,
        }

        if not self._shell_ready:
            return info

        if self._shell_type == "mikrotik":
            return self._get_wan_info_mikrotik()

        # Linux/BusyBox/ZTE shell
        output = ""
        for cmd in ["ifconfig", "ip addr show", "ip route"]:
            output += self._run_cmd(cmd, wait=2.0) + "\n"

        # PPPoE peers
        for cmd in [
            "cat /etc/ppp/peers/pppoe* 2>/dev/null",
            "cat /etc/ppp/options 2>/dev/null",
            "ps 2>/dev/null | grep pppd",
        ]:
            output += self._run_cmd(cmd, wait=1.5) + "\n"

        parsed = _extract_pppoe_from_output(output)
        info.update({k: v for k, v in parsed.items() if v is not None})
        return info

    def _get_wan_info_mikrotik(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {"wan_ip": None, "gateway": None, "mode": "Unknown",
                                 "pppoe_user": None, "vendor": self.vendor_name}
        ip_out = self._run_cmd("/ip address print", wait=2.0)
        ppp_out = self._run_cmd("/ppp active print", wait=2.0)

        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+\s+\S+\s+\S+\s+(\S+)", ip_out)
        if ip_match:
            info["wan_ip"] = ip_match.group(1)

        user_match = re.search(r"name=(\S+)", ppp_out)
        if user_match:
            info["pppoe_user"] = user_match.group(1)
            info["mode"] = "PPPoE"

        return info

    # ------------------------------------------------------------------
    def configure_wan(self, wan_config: Dict[str, Any]) -> Tuple[bool, str]:
        if not self._shell_ready:
            return False, "Belum login Telnet"

        mode      = wan_config.get("mode", "PPPoE")
        pppoe_usr = wan_config.get("pppoe_username", "")
        pppoe_pwd = wan_config.get("pppoe_password", "")
        vlan_id   = wan_config.get("vlan_id", "")

        if self._shell_type == "mikrotik":
            return self._configure_wan_mikrotik(mode, pppoe_usr, pppoe_pwd, vlan_id)

        # Linux / BusyBox / ZTE shell
        out = ""
        if mode == "PPPoE" and pppoe_usr:
            # OpenWRT / uci style
            r = self._run_cmd("uci show network.wan.proto 2>/dev/null", wait=1.0)
            if "pppoe" in r.lower() or "proto" in r.lower():
                # OpenWRT uci
                cmds = [
                    f"uci set network.wan.proto='pppoe'",
                    f"uci set network.wan.username='{pppoe_usr}'",
                    f"uci set network.wan.password='{pppoe_pwd}'",
                ]
                if vlan_id:
                    cmds.append(f"uci set network.wan.vid='{vlan_id}'")
                cmds.append("uci commit network")
                cmds.append("/etc/init.d/network restart")
                for c in cmds:
                    out += self._run_cmd(c, wait=1.5)
                if "Error" not in out and "failed" not in out.lower():
                    return True, f"WAN PPPoE dikonfigurasi via Telnet (uci): user={pppoe_usr}"
            else:
                # Busybox / NVRAM style (Broadcom, old ZTE)
                cmds = [
                    f"nvram set wan_proto=pppoe",
                    f"nvram set ppp_username='{pppoe_usr}'",
                    f"nvram set ppp_passwd='{pppoe_pwd}'",
                ]
                if vlan_id:
                    cmds.append(f"nvram set wan_vlanid='{vlan_id}'")
                cmds.append("nvram commit")
                for c in cmds:
                    out += self._run_cmd(c, wait=1.0)
                # Try to restart WAN
                self._run_cmd("killall pppd 2>/dev/null; sleep 1; pppd &", wait=2.0)
                return True, f"WAN PPPoE dikonfigurasi via Telnet (nvram): user={pppoe_usr}"

        elif mode == "DHCP":
            r = self._run_cmd("uci show network.wan.proto 2>/dev/null", wait=1.0)
            if "proto" in r.lower():
                self._run_cmd("uci set network.wan.proto='dhcp'", wait=1.0)
                self._run_cmd("uci commit network", wait=1.0)
                self._run_cmd("/etc/init.d/network restart", wait=2.0)
            else:
                self._run_cmd("nvram set wan_proto=dhcp && nvram commit", wait=1.5)
            return True, "WAN DHCP dikonfigurasi via Telnet"

        return False, f"Mode WAN '{mode}' tidak didukung atau perintah gagal"

    def _configure_wan_mikrotik(self, mode: str, user: str, pwd: str, vlan: str) -> Tuple[bool, str]:
        if mode == "PPPoE" and user:
            # Find existing PPPoE client interface
            out = self._run_cmd("/interface pppoe-client print", wait=2.0)
            iface = "pppoe-out1"
            m = re.search(r"(\S+-\S+)\s+.*pppoe", out, re.IGNORECASE)
            if m:
                iface = m.group(1)
            self._run_cmd(f"/interface pppoe-client set {iface} user=\"{user}\" password=\"{pwd}\"", wait=1.5)
            self._run_cmd(f"/interface pppoe-client enable {iface}", wait=1.0)
            return True, f"PPPoE MikroTik dikonfigurasi via Telnet: user={user} pada {iface}"
        return False, "Konfigurasi WAN MikroTik via Telnet: mode tidak dikenali"

    # ------------------------------------------------------------------
    def configure_wlan_ssid(self, ssid_config: Dict[str, Any]) -> Tuple[bool, str]:
        if not self._shell_ready:
            return False, "Belum login Telnet"

        ssid_name = ssid_config.get("ssid_name", "")
        password  = ssid_config.get("password", "")
        enable    = ssid_config.get("enable", True)
        auth_mode = ssid_config.get("auth_mode", "WPA2-PSK")
        ssid_idx  = int(ssid_config.get("ssid_index", 1))

        if self._shell_type == "mikrotik":
            # MikroTik CAPsMAN / simple wireless
            action = "enable" if enable else "disable"
            if ssid_name:
                self._run_cmd(f"/interface wireless set wlan1 ssid=\"{ssid_name}\"", wait=1.5)
            if password:
                self._run_cmd(f"/interface wireless security-profiles set default authentication-types=wpa2-psk mode=dynamic-keys wpa2-pre-shared-key=\"{password}\"", wait=1.5)
            self._run_cmd(f"/interface wireless {action} wlan1", wait=1.0)
            return True, f"Wi-Fi MikroTik dikonfigurasi via Telnet: SSID={ssid_name}"

        # OpenWRT / uci (most Linux-based ONT)
        r = self._run_cmd("uci show wireless 2>/dev/null | head -5", wait=1.0)
        if "wireless" in r.lower():
            radio = f"default_radio{ssid_idx - 1}" if ssid_idx > 1 else "default_radio0"
            cmds = [f"uci set wireless.{radio}.disabled={'0' if enable else '1'}"]
            if ssid_name:
                cmds.append(f"uci set wireless.{radio}.ssid='{ssid_name}'")
            if password and auth_mode != "Open":
                cmds.append(f"uci set wireless.{radio}.encryption='psk2'")
                cmds.append(f"uci set wireless.{radio}.key='{password}'")
            else:
                cmds.append(f"uci set wireless.{radio}.encryption='none'")
            cmds += ["uci commit wireless", "wifi reload"]
            for c in cmds:
                self._run_cmd(c, wait=1.5)
            return True, f"Wi-Fi dikonfigurasi via Telnet (uci): SSID={ssid_name}"

        # NVRAM style (Broadcom, older routers)
        if ssid_name:
            self._run_cmd(f"nvram set wl0_ssid='{ssid_name}'", wait=1.0)
        if password and auth_mode != "Open":
            self._run_cmd(f"nvram set wl0_akm='psk2'", wait=1.0)
            self._run_cmd(f"nvram set wl0_wpa_psk='{password}'", wait=1.0)
        else:
            self._run_cmd("nvram set wl0_akm=''", wait=1.0)
        self._run_cmd("nvram commit", wait=1.5)
        self._run_cmd("killall -HUP nas 2>/dev/null; killall -HUP wpa_supplicant 2>/dev/null", wait=1.0)
        return True, f"Wi-Fi dikonfigurasi via Telnet (nvram): SSID={ssid_name}"

    # ------------------------------------------------------------------
    def configure_lan_ports(self, lan_config: Dict[str, Any]) -> Tuple[bool, str]:
        if not self._shell_ready:
            return False, "Belum login Telnet"

        enable = lan_config.get("enable", True)
        ports  = lan_config.get("ports", {})

        if self._shell_type == "mikrotik":
            for port_name, state in ports.items():
                action = "enable" if state else "disable"
                iface = port_name.replace("lan", "ether")
                self._run_cmd(f"/interface ethernet {action} {iface}", wait=1.0)
            return True, f"Port LAN MikroTik dikonfigurasi via Telnet"

        # Linux: ip link set ethX up/down
        results = []
        port_map = {"lan1": "eth1", "lan2": "eth2", "lan3": "eth3", "lan4": "eth4"}
        if not ports:
            # Toggle all
            action = "up" if enable else "down"
            for eth in ["eth1", "eth2", "eth3", "eth4"]:
                out = self._run_cmd(f"ip link set {eth} {action} 2>/dev/null", wait=0.8)
                results.append(eth)
        else:
            for port_key, state in ports.items():
                eth = port_map.get(port_key, port_key)
                action = "up" if state else "down"
                self._run_cmd(f"ip link set {eth} {action} 2>/dev/null", wait=0.8)
                results.append(f"{eth}={'UP' if state else 'DOWN'}")

        return True, f"Port LAN dikonfigurasi via Telnet: {', '.join(results)}"



    def change_password(self, new_password: str, username: str = "admin") -> Tuple[bool, str]:
        if not self._shell_ready:
            return False, "Belum login"
        # Linux passwd command
        self._run_cmd(f"passwd {username}", wait=1.0)
        self._session.write(new_password)
        self._session.read_until("New password", "password:", timeout=2.0)
        self._session.write(new_password)
        out = self._session.read_until(*SHELL_PROMPTS, timeout=2.0)
        if "updated" in out.lower() or "changed" in out.lower() or "$" in out or "#" in out:
            return True, f"Password {username} berhasil diubah via Telnet"
        return False, "Gagal mengubah password via Telnet"

    def reboot(self) -> Tuple[bool, str]:
        if not self._shell_ready:
            return False, "Belum login"
        if self._shell_type == "mikrotik":
            self._run_cmd("/system reboot", wait=0.5)
        else:
            self._run_cmd("reboot", wait=0.5)
        return True, "Perintah reboot dikirim via Telnet"

    def __del__(self):
        if getattr(self, "_session", None):
            try:
                self._session.close()
            except Exception:
                pass
