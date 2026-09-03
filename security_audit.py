import socket
import time
import struct
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Optional

from credentials import get_credentials, DEFAULT_CREDENTIALS
from adapters.telnet import TelnetSession

# High-risk ports to audit on each target ONT
AUDIT_PORTS = {
    21: {"service": "FTP", "risk": "MEDIUM", "desc": "File Transfer Protocol (Cleartext)"},
    22: {"service": "SSH", "risk": "LOW", "desc": "Secure Shell Remote Access"},
    23: {"service": "Telnet", "risk": "HIGH", "desc": "Insecure Cleartext Terminal (Botnet Target)"},
    53: {"service": "DNS", "risk": "MEDIUM", "desc": "DNS Server Port (Potential Open Resolver)"},
    80: {"service": "HTTP Web", "risk": "INFO", "desc": "Web Management GUI"},
    161: {"service": "SNMP", "risk": "MEDIUM", "desc": "SNMP Network Management (Information Disclosure)"},
    443: {"service": "HTTPS Web", "risk": "INFO", "desc": "Secure Web Management GUI"},
    7547: {"service": "TR-069 CWMP", "risk": "HIGH", "desc": "TR-069 Remote Management (ACS Target)"},
    8080: {"service": "HTTP-Alt", "risk": "INFO", "desc": "Alternate Web Management GUI"},
}

def probe_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Check if a TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

def probe_open_dns_resolver(ip: str, timeout: float = 1.0) -> bool:
    """
    Test if the target responds to recursive DNS queries (Open DNS Resolver test).
    Sends a standard DNS query for google.com.
    """
    try:
        dns_query = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06google\x03com\x00\x00\x01\x00\x01"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(dns_query, (ip, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) > 12 and data[:2] == b"\x12\x34":
            return True
    except Exception:
        pass
    return False

def probe_snmp_public(ip: str, timeout: float = 1.0) -> bool:
    """
    Test if SNMP responds with default 'public' community string.
    Sends an SNMPv2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0).
    """
    try:
        snmp_packet = (
            b"\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x12\x34\x56\x78"
            b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02"
            b"\x01\x01\x01\x00\x05\x00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(snmp_packet, (ip, 161))
        data, _ = sock.recvfrom(512)
        sock.close()
        return len(data) > 0
    except Exception:
        pass
    return False

def probe_telnet_credentials(ip: str, timeout: float = 2.5) -> List[Tuple[str, str]]:
    """
    Attempt login on Telnet port 23 with high-risk factory root/admin credentials.
    """
    successful_creds = []
    telnet_test_pairs = [
        ("root", "Zte521"),
        ("root", "admin"),
        ("root", "adminHW"),
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "telkomdso123"),
        ("telecomadmin", "admintelecom"),
    ]

    for user, pwd in telnet_test_pairs:
        try:
            sess = TelnetSession(ip, port=23, timeout=timeout)
            if not sess.connect():
                break
            
            banner = sess.read_until("Login:", "login:", "Username:", "username:", timeout=1.5)
            if any(p in banner.lower() for p in ["login:", "username:"]):
                sess.send(user)
                pwd_prompt = sess.read_until("Password:", "password:", timeout=1.5)
                if "password:" in pwd_prompt.lower():
                    sess.send(pwd)
                    res = sess.read_until("#", ">", "$", "Login incorrect", "failed", timeout=1.5)
                    if any(shell_char in res for shell_char in ["#", ">", "$"]) and "incorrect" not in res.lower() and "failed" not in res.lower():
                        successful_creds.append((user, pwd))
            sess.close()
            if successful_creds:
                break
        except Exception:
            pass

    return successful_creds

def audit_single_device(
    device: Dict[str, Any],
    custom_creds: Optional[List[Tuple[str, str]]] = None,
    timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Execute a comprehensive penetration test / vulnerability audit on a single ONT target.
    """
    ip = device["ip"]
    vendor = device.get("vendor", "Generic")
    mac = device.get("mac", "")
    adapter = device.get("adapter")
    creds_list = custom_creds or get_credentials()

    vulnerabilities = []
    open_audit_ports = []
    tested_creds_matched = []
    telnet_backdoors = []
    is_open_dns = False
    is_snmp_exposed = False
    wan_audit = {}

    # 1. Port & Attack Surface Probing
    for port, meta in AUDIT_PORTS.items():
        if probe_port(ip, port, timeout=0.8):
            open_audit_ports.append(port)
            if port == 23:
                vulnerabilities.append({
                    "id": "VULN-TELNET-OPEN",
                    "severity": "HIGH",
                    "name": "Port Telnet (23) Terbuka Tanpa Enkripsi",
                    "desc": "Akses terminal Telnet terbuka di jaringan lokal/WAN. Rentan sniffing kredensial dan serangan botnet IoT."
                })
            elif port == 7547:
                vulnerabilities.append({
                    "id": "VULN-TR069-EXPOSED",
                    "severity": "MEDIUM",
                    "name": "Port TR-069 CWMP (7547) Terekspos",
                    "desc": "Port manajemen jarak jauh TR-069 terbuka. Berpotensi rentan eksploitasi jika firmware tidak ter-patch."
                })
            elif port == 21:
                vulnerabilities.append({
                    "id": "VULN-FTP-OPEN",
                    "severity": "MEDIUM",
                    "name": "Service FTP (Port 21) Terbuka",
                    "desc": "FTP terbuka dengan protokol plain-text tanpa enkripsi TLS."
                })

    # 2. Open DNS Resolver Probe (Port 53 UDP)
    if 53 in open_audit_ports or probe_port(ip, 53, timeout=0.5):
        if probe_open_dns_resolver(ip, timeout=1.2):
            is_open_dns = True
            vulnerabilities.append({
                "id": "VULN-OPEN-DNS-RESOLVER",
                "severity": "HIGH",
                "name": "Open Recursive DNS Resolver",
                "desc": "ONT merespon query DNS eksternal/rekursif. Dapat dimanfaatkan sebagai pemantul serangan DNS Amplification DDoS."
            })

    # 3. SNMP Public Community Probe (Port 161 UDP)
    if probe_snmp_public(ip, timeout=1.0):
        is_snmp_exposed = True
        vulnerabilities.append({
            "id": "VULN-SNMP-DEFAULT-COMMUNITY",
            "severity": "HIGH",
            "name": "SNMP Terbuka dengan Default Community 'public'",
            "desc": "Perangkat merespon SNMP GetRequest menggunakan community 'public'. Penyerang dapat membaca topologi, interface, dan data traffic."
        })

    # 4. Telnet Backdoor / Default Root Credential Probe
    if 23 in open_audit_ports:
        telnet_backdoors = probe_telnet_credentials(ip, timeout=2.0)
        if telnet_backdoors:
            for u, p in telnet_backdoors:
                vulnerabilities.append({
                    "id": "VULN-TELNET-ROOT-BACKDOOR",
                    "severity": "CRITICAL",
                    "name": f"Kredensial Root/Admin Telnet Default Aktif ({u}:{p})",
                    "desc": f"Ditemukan akses shell Telnet dengan kredensial default pabrik '{u}:{p}'. Akses kontrol penuh dapat diambil alih."
                })

    # 5. Web Management Authentication & Default Credential Brute-Force
    login_success = False
    active_user = None
    active_pass = None

    if adapter:
        for u, p in creds_list:
            success, msg = adapter.login(u, p)
            if success:
                login_success = True
                active_user = u
                active_pass = p
                tested_creds_matched.append((u, p))
                
                is_known_factory_default = any(u == def_u and p == def_p for def_u, def_p in DEFAULT_CREDENTIALS)
                if is_known_factory_default:
                    severity = "CRITICAL" if u.lower() in ["telecomadmin", "root", "epadmin"] else "HIGH"
                    vulnerabilities.append({
                        "id": "VULN-DEFAULT-WEB-CREDENTIAL",
                        "severity": severity,
                        "name": f"Password Web Admin Default Pabrikan ({u}:{p})",
                        "desc": f"ONT masih menggunakan kredensial bawaan pabrik '{u}:{p}'. Siapapun di jaringan dapat masuk dan mengubah setting."
                    })
                break

    # 6. Deep Configuration Audit (If Authenticated)
    if login_success and adapter:
        try:
            wan_info = adapter.get_wan_info()
            if wan_info:
                wan_audit = wan_info
                if wan_info.get("mode") == "Bridge":
                    vulnerabilities.append({
                        "id": "INFO-WAN-BRIDGE",
                        "severity": "INFO",
                        "name": "Mode WAN Bridge Aktif",
                        "desc": "Perangkat beroperasi dalam mode Bridge (dial PPPoE dilakukan oleh router hilir)."
                    })
        except Exception:
            pass

    # 7. Calculate Overall Risk Score & Posture
    severities = [v["severity"] for v in vulnerabilities]
    if "CRITICAL" in severities:
        risk_level = "CRITICAL"
        risk_color = "bold red"
        risk_score = 9.5
    elif "HIGH" in severities:
        risk_level = "HIGH"
        risk_color = "red"
        risk_score = 7.5
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
        risk_color = "yellow"
        risk_score = 5.0
    elif "LOW" in severities:
        risk_level = "LOW"
        risk_color = "cyan"
        risk_score = 3.0
    else:
        risk_level = "SECURE"
        risk_color = "bold green"
        risk_score = 0.0

    return {
        "ip": ip,
        "vendor": vendor,
        "mac": mac,
        "device_type": device.get("device_type", "ONT"),
        "open_ports": open_audit_ports,
        "login_success": login_success,
        "active_user": active_user,
        "active_pass": active_pass,
        "telnet_backdoors": telnet_backdoors,
        "is_open_dns": is_open_dns,
        "is_snmp_exposed": is_snmp_exposed,
        "vulnerabilities": vulnerabilities,
        "vuln_count": len(vulnerabilities),
        "risk_level": risk_level,
        "risk_color": risk_color,
        "risk_score": risk_score,
        "wan_audit": wan_audit,
    }

def run_batch_pentest(
    devices: List[Dict[str, Any]],
    custom_creds: Optional[List[Tuple[str, str]]] = None,
    max_workers: int = 15,
    callback = None
) -> List[Dict[str, Any]]:
    """
    Execute multi-threaded penetration testing across a list of discovered devices.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(audit_single_device, dev, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: (-r["risk_score"], r["ip"]))

def detect_rogue_dhcp_servers(timeout: float = 3.0) -> List[Dict[str, str]]:
    """
    Send a broadcast DHCP Discover packet on the local LAN interface to detect rogue DHCP servers.
    Returns a list of responding DHCP servers (IP and offered IP).
    """
    rogue_servers = []
    try:
        xid = b"\x39\x03\xf3\x26"
        mac_bytes = b"\x00\x11\x22\x33\x44\x55"
        
        bootp_packet = (
            b"\x01\x01\x06\x00"
            + xid
            + b"\x00\x00\x80\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + mac_bytes + (b"\x00" * 10)
            + (b"\x00" * 64)
            + (b"\x00" * 128)
            + b"\x63\x82\x53\x63"
            + b"\x35\x01\x01"
            + b"\x37\x04\x01\x03\x06\x2a"
            + b"\xff"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)

        sock.sendto(bootp_packet, ("255.255.255.255", 67))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
                server_ip = addr[0]
                if data and len(data) >= 240 and data[:1] == b"\x02":
                    offered_ip = socket.inet_ntoa(data[16:20])
                    if not any(s["server_ip"] == server_ip for s in rogue_servers):
                        rogue_servers.append({
                            "server_ip": server_ip,
                            "offered_ip": offered_ip,
                        })
            except socket.timeout:
                break
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    return rogue_servers
