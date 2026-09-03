import socket
import json
import re
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from adapters.zte import ZTEAdapter
from adapters.huawei import HuaweiAdapter
from adapters.fiberhome import FiberhomeAdapter
from adapters.vsol import VSOLAdapter
from adapters.tenda import TendaAdapter
from adapters.tplink import TPLinkAdapter
from adapters.mikrotik import MikrotikAdapter
from adapters.generic import GenericAdapter
from adapters.telnet import TelnetAdapter

ADAPTERS = [
    ZTEAdapter,
    HuaweiAdapter,
    FiberhomeAdapter,
    VSOLAdapter,
    TendaAdapter,
    TPLinkAdapter,
    MikrotikAdapter,
    GenericAdapter,
]

# MAC OUI Vendor Table for Hardware Detection
MAC_OUI_TABLE = {
    # Tenda
    "c8:3a:35": "Tenda Router", "cc:2d:21": "Tenda Router", "50:2b:73": "Tenda Router",
    "04:95:e6": "Tenda Router", "08:40:f3": "Tenda Router", "d8:32:14": "Tenda Router",
    "ec:22:80": "Tenda Router", "50:0f:f5": "Tenda Router",
    # TP-Link
    "50:d4:f7": "TP-Link Router", "e8:48:b8": "TP-Link Router", "ec:08:6b": "TP-Link Router",
    "14:cc:20": "TP-Link Router", "f4:ec:38": "TP-Link Router", "54:e6:fc": "TP-Link Router",
    "00:31:92": "TP-Link Router", "70:4f:57": "TP-Link Router", "98:da:c4": "TP-Link Router",
    "18:d6:c7": "TP-Link Router", "1c:3b:f3": "TP-Link Router", "50:c7:bf": "TP-Link Router",
    "60:32:b1": "TP-Link Router", "74:05:a5": "TP-Link Router", "90:f6:52": "TP-Link Router",
    "a0:f3:c1": "TP-Link Router", "b0:4e:26": "TP-Link Router", "c0:25:e9": "TP-Link Router",
    "c4:6e:1f": "TP-Link Router", "d8:07:b6": "TP-Link Router", "e4:c3:2a": "TP-Link Router",
    # ZTE
    "14:ad:ca": "ZTE Corporation", "74:a7:8e": "ZTE Corporation", "a0:ec:80": "ZTE Corporation",
    "84:74:2a": "ZTE Corporation", "38:97:d6": "ZTE Corporation", "68:72:51": "ZTE Corporation",
    "c8:d3:a3": "ZTE Corporation", "d4:6e:0e": "ZTE Corporation", "00:19:c6": "ZTE Corporation",
    "00:22:93": "ZTE Corporation", "2c:95:7f": "ZTE Corporation", "34:e0:cf": "ZTE Corporation",
    "48:28:2f": "ZTE Corporation", "70:9f:2d": "ZTE Corporation", "58:4b:bc": "ZTE Corporation",
    # Huawei
    "a0:08:6f": "Huawei Technologies", "cc:96:a0": "Huawei Technologies", "48:43:5a": "Huawei Technologies",
    "70:72:3c": "Huawei Technologies", "20:0b:c7": "Huawei Technologies", "f8:4a:bf": "Huawei Technologies",
    "00:1e:10": "Huawei Technologies", "00:25:9e": "Huawei Technologies", "00:46:4b": "Huawei Technologies",
    "0c:96:bf": "Huawei Technologies", "10:51:72": "Huawei Technologies", "14:b9:68": "Huawei Technologies",
    "28:6e:d4": "Huawei Technologies", "40:4d:8e": "Huawei Technologies", "4c:b1:6c": "Huawei Technologies",
    "5c:7d:5e": "Huawei Technologies", "78:6a:89": "Huawei Technologies", "80:b6:86": "Huawei Technologies",
    "ac:85:3d": "Huawei Technologies", "c8:d1:5e": "Huawei Technologies", "e0:19:1d": "Huawei Technologies",
    "e4:68:a3": "Huawei Technologies", "f4:c4:d1": "Huawei Technologies",
    # FiberHome
    "84:d8:1b": "Fiberhome", "f4:b3:81": "Fiberhome", "30:b5:c2": "Fiberhome",
    "00:0a:c2": "Fiberhome", "00:18:82": "Fiberhome", "78:44:fd": "Fiberhome",
    "94:04:9c": "Fiberhome", "a0:93:5b": "Fiberhome", "d0:76:8f": "Fiberhome",
    # VSOL / C-Data / Realtek / XPON / EPON
    "e0:67:b3": "VSOL / C-Data", "00:e0:4c": "Realtek / XPON ONU", "00:18:e7": "C-Data XPON ONU",
    "28:2c:02": "VSOL XPON ONU", "3c:df:bd": "VSOL XPON ONU", "80:89:17": "C-Data XPON ONU",
    "98:0d:2e": "C-Data XPON ONU", "c4:ad:34": "VSOL XPON ONU", "dc:ef:09": "XPON Stick/ONU",
    # HSGQ / HIOSO / BDCOM (Modem LAN / EPON ONU)
    "00:1f:ce": "HSGQ EPON/GPON ONU", "00:0b:2f": "HIOSO EPON ONU", "00:23:cd": "BDCOM EPON/GPON ONU",
    "48:8a:d2": "HSGQ EPON ONU", "54:22:f8": "HIOSO EPON ONU", "6c:b0:ce": "BDCOM ONU",
    # Totolink / Mercusys / D-Link
    "44:55:c4": "Totolink Router", "78:44:76": "Totolink Router", "d8:15:0d": "Totolink Router",
    "00:18:82": "Huawei Technologies",
    "00:1e:10": "Huawei Technologies",
    "00:25:68": "Huawei Technologies",
    "00:25:9e": "Huawei Technologies",
    "04:25:c5": "Huawei Technologies",
    "08:19:a6": "Huawei Technologies",
    "0c:37:dc": "Huawei Technologies",
    "10:1b:54": "Huawei Technologies",
    "14:b9:68": "Huawei Technologies",
    "1c:1d:67": "Huawei Technologies",
    "20:08:ed": "Huawei Technologies",
    "24:69:a5": "Huawei Technologies",
    "28:6e:d4": "Huawei Technologies",
    "2c:ab:00": "Huawei Technologies",
    "30:87:30": "Huawei Technologies",
    "34:6b:d3": "Huawei Technologies",
    "38:f2:9e": "Huawei Technologies",
    "40:4d:8e": "Huawei Technologies",
    "48:62:76": "Huawei Technologies",
    "4c:b1:6c": "Huawei Technologies",
    "50:9f:27": "Huawei Technologies",
    "54:89:98": "Huawei Technologies",
    "58:2a:f7": "Huawei Technologies",
    "60:de:44": "Huawei Technologies",
    "68:a0:f6": "Huawei Technologies",
    "70:7b:e8": "Huawei Technologies",
    "78:6a:89": "Huawei Technologies",
    "80:b6:86": "Huawei Technologies",
    "84:5b:12": "Huawei Technologies",
    "88:86:03": "Huawei Technologies",
    "8c:34:fd": "Huawei Technologies",
    "90:4e:91": "Huawei Technologies",
    "94:04:9c": "Huawei Technologies",
    "9c:28:ef": "Huawei Technologies",
    "a4:ba:76": "Huawei Technologies",
    "ac:e8:7b": "Huawei Technologies",
    "b4:15:13": "Huawei Technologies",
    "bc:25:e0": "Huawei Technologies",
    "c4:07:2f": "Huawei Technologies",
    "cc:cc:81": "Huawei Technologies",
    "d0:7a:b5": "Huawei Technologies",
    "d8:49:0b": "Huawei Technologies",
    "dc:d2:fc": "Huawei Technologies",
    "e0:24:7f": "Huawei Technologies",
    "e8:08:8b": "Huawei Technologies",
    "f4:55:95": "Huawei Technologies",
    "f8:e7:1e": "Huawei Technologies",
    "fc:48:ef": "Huawei Technologies",

    # Fiberhome
    "00:0a:eb": "Fiberhome Telecommunication",
    "08:e8:4f": "Fiberhome Telecommunication",
    "10:c0:59": "Fiberhome Telecommunication",
    "18:68:cb": "Fiberhome Telecommunication",
    "2c:97:b1": "Fiberhome Telecommunication",
    "38:83:45": "Fiberhome Telecommunication",
    "40:31:3c": "Fiberhome Telecommunication",
    "48:7b:6b": "Fiberhome Telecommunication",
    "58:63:9a": "Fiberhome Telecommunication",
    "70:a8:e3": "Fiberhome Telecommunication",
    "74:05:a5": "Fiberhome Telecommunication",
    "80:fb:06": "Fiberhome Telecommunication",
    "8c:a6:df": "Fiberhome Telecommunication",
    "90:21:55": "Fiberhome Telecommunication",
    "94:77:2b": "Fiberhome Telecommunication",
    "a0:ec:f9": "Fiberhome Telecommunication",
    "b4:30:52": "Fiberhome Telecommunication",
    "c8:1f:66": "Fiberhome Telecommunication",
    "cc:96:e5": "Fiberhome Telecommunication",
    "dc:ee:06": "Fiberhome Telecommunication",
    "e4:c3:2a": "Fiberhome Telecommunication",
    "f8:4a:bf": "Fiberhome Telecommunication",

    # MikroTik
    "00:0c:42": "MikroTik RouterOS",
    "2c:c8:1b": "MikroTik RouterOS",
    "48:8f:5a": "MikroTik RouterOS",
    "4c:5e:0c": "MikroTik RouterOS",
    "64:d1:54": "MikroTik RouterOS",
    "6c:3b:6b": "MikroTik RouterOS",
    "74:4d:28": "MikroTik RouterOS",
    "78:9a:18": "MikroTik RouterOS",
    "b8:69:f4": "MikroTik RouterOS",
    "c4:ad:34": "MikroTik RouterOS",
    "cc:2d:e0": "MikroTik RouterOS",
    "d4:01:c3": "MikroTik RouterOS",
    "d4:ca:6d": "MikroTik RouterOS",
    "e4:8d:8c": "MikroTik RouterOS",

    # TP-Link
    "14:cc:20": "TP-Link Technologies",
    "1c:3b:f3": "TP-Link Technologies",
    "30:de:4b": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "60:32:b1": "TP-Link Technologies",
    "70:4f:57": "TP-Link Technologies",
    "74:05:a5": "TP-Link Technologies",
    "98:48:27": "TP-Link Technologies",
    "a8:57:4e": "TP-Link Technologies",
    "b0:95:75": "TP-Link Technologies",
    "c0:25:e9": "TP-Link Technologies",
    "c0:4a:00": "TP-Link Technologies",
    "e8:48:b8": "TP-Link Technologies",
    "f4:ec:38": "TP-Link Technologies",

    # Tenda
    "04:95:e6": "Tenda Technology",
    "50:2b:73": "Tenda Technology",
    "c8:3a:35": "Tenda Technology",
    "cc:2d:21": "Tenda Technology",
    "e8:65:d4": "Tenda Technology",

    # Totolink / Zioncom
    "00:15:ad": "Zioncom (Totolink)",
    "78:44:76": "Zioncom (Totolink)",
    "d8:15:0d": "Zioncom (Totolink)",

    # VSOL / C-Data / Realtek
    "00:e0:4c": "Realtek Semiconductor (VSOL/XPON)",
    "80:8f:1d": "VSOL / C-Data XPON ONU",
    "00:1f:ce": "Cognitive XPON ONU",
    "1c:fa:68": "C-Data Technology",
    "28:2c:02": "Realtek XPON ONU",
    "50:04:b8": "C-Data Technology",
    "80:89:17": "C-Data Technology",
    "bc:54:51": "HSGQ / XPON ONU",
}

def get_active_subnets() -> List[Dict[str, str]]:
    """
    Detect all active network interfaces and their IPv4 subnets.
    Zero Netlink Dependency: Uses /proc/net and sockets for 100% Android/Termux & Linux compatibility.
    """
    subnets = []

    # 1. Try /proc/net/route for active interfaces
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 8 and parts[0] != "lo":
                        iface = parts[0]
                        dest_hex = parts[1]
                        mask_hex = parts[7]
                        if mask_hex != "00000000":
                            dest_ip = socket.inet_ntoa(struct.pack("<L", int(dest_hex, 16)))
                            mask_ip = socket.inet_ntoa(struct.pack("<L", int(mask_hex, 16)))
                            net = ipaddress.IPv4Network(f"{dest_ip}/{mask_ip}", strict=False)
                            if not any(s['subnet'] == str(net) for s in subnets):
                                subnets.append({'iface': iface, 'ip': dest_ip, 'subnet': str(net)})
    except Exception:
        pass

    # 2. Try Linux standard ip -j addr (with stderr suppression)
    if not subnets:
        try:
            out = subprocess.check_output(['ip', '-j', 'addr'], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
            data = json.loads(out)
            for iface in data:
                if iface.get('operstate') == 'UP' and iface.get('ifname') != 'lo':
                    for addr in iface.get('addr_info', []):
                        if addr.get('family') == 'inet':
                            ip = addr.get('local')
                            prefix = addr.get('prefixlen')
                            net = ipaddress.IPv4Network(f'{ip}/{prefix}', strict=False)
                            subnets.append({
                                'iface': iface.get('ifname'),
                                'ip': ip,
                                'subnet': str(net)
                            })
        except Exception:
            pass

    # 3. Fallback to socket detection if no subnets detected
    if not subnets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            subnets.append({'iface': 'default', 'ip': local_ip, 'subnet': str(net)})
        except Exception:
            subnets.append({'iface': 'default', 'ip': '192.168.1.1', 'subnet': '192.168.1.0/24'})

    return subnets

def get_default_gateway() -> Optional[Dict[str, str]]:
    """
    Detect the default gateway IP and interface from routing table.
    Uses /proc/net/route first to avoid 'cannot bind netlink socket' on Android / Termux.
    """
    # 1. Pure Python /proc/net/route parsing (Fastest & No Netlink socket error)
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route", "r") as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        gw_hex = fields[2]
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                        return {"gateway_ip": gw_ip, "iface": fields[0]}
    except Exception:
        pass

    # 2. Try 'ip route' command with suppressed stderr
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default'], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
        m = re.search(r'default via ([\d\.]+) dev (\w+)', out)
        if m:
            return {'gateway_ip': m.group(1), 'iface': m.group(2)}
    except Exception:
        pass

    # 3. Fallback socket estimation
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        gw_est = local_ip.rsplit(".", 1)[0] + ".1"
        return {'gateway_ip': gw_est, 'iface': 'default'}
    except Exception:
        pass

    return None

def get_arp_table() -> Dict[str, Dict[str, str]]:
    """
    Parse local ARP neighbor cache to obtain IP to MAC and OUI vendor mapping.
    Uses /proc/net/arp directly to prevent netlink permission errors.
    """
    table = {}

    # 1. Direct /proc/net/arp reading
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].lower()
                        if mac and mac != "00:00:00:00:00:00" and ":" in mac:
                            prefix = ":".join(mac.split(":")[:3])
                            vendor_hint = MAC_OUI_TABLE.get(prefix, "")
                            table[ip] = {
                                "mac": mac,
                                "vendor_hint": vendor_hint,
                            }
            if table:
                return table
    except Exception:
        pass

    # 2. Subprocess fallback with stderr suppression
    try:
        out = subprocess.check_output(['ip', 'neigh'], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and 'FAILED' not in line:
                ip = parts[0]
                mac = parts[4].lower() if len(parts) > 4 and ":" in parts[4] else ""
                if ip and mac and not ip.startswith('fe80:'):
                    prefix = ":".join(mac.split(":")[:3])
                    vendor_hint = MAC_OUI_TABLE.get(prefix, "")
                    table[ip] = {
                        "mac": mac,
                        "vendor_hint": vendor_hint,
                    }
    except Exception:
        pass
    return table

def get_arp_neighbors() -> List[str]:
    """
    Get all active neighbor IP addresses from system ARP cache.
    """
    return list(get_arp_table().keys())

def get_default_local_subnet() -> str:
    gw = get_default_gateway()
    if gw:
        gw_ip = gw['gateway_ip']
        net = ipaddress.IPv4Network(f"{gw_ip}/24", strict=False)
        return str(net)
    active = get_active_subnets()
    return active[0]['subnet'] if active else "192.168.1.0/24"

def check_port(ip: str, port: int = 80, timeout: float = 0.25) -> bool:
    """
    Check if a TCP port is open on the target IP with fast socket timeout.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def get_device_category(vendor_str: str) -> str:
    """
    Classify device into:
    - Modem LAN (ONU 1-Port) (HSGQ, HIOSO, BDCOM, V2801, FD511, HG8310M, F401, etc.)
    - Modem ONT (Multi-Port & Wi-Fi GPON/XPON/EPON)
    - Router Wi-Fi / AP (SOHO Routers)
    - Gateway / MikroTik
    - Klien Hotspot
    - Perangkat Jaringan
    """
    v = (vendor_str or "").lower()
    if "klien hotspot" in v or "hotspot user" in v or "terintersepsi" in v:
        return "Klien Hotspot"
    if any(k in v for k in ["modem lan", "1-port", "onu 1-port", "1ge", "1fe", "bridge onu", "hsgq", "hioso", "bdcom", "v2801", "fd511", "hg8310", "hg8010", "f401", "f601", "an5506-01"]):
        return "Modem LAN (ONU 1-Port)"
    if any(k in v for k in ["gm220", "f609", "f660", "f670", "hg8245", "eg8145", "an5506-04", "an5506-02", "ont", "xpon ont", "gpon ont"]):
        return "Modem ONT"
    if any(k in v for k in ["tenda", "tp-link", "tplink", "totolink", "mercusys", "netis", "d-link", "router wi-fi", "access point"]):
        return "Router Wi-Fi / AP"
    if "mikrotik" in v or "routeros" in v:
        return "Gateway / MikroTik"
    return "Perangkat Jaringan"

def scan_host(ip: str, arp_table: Dict[str, Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """
    Ultra-fast staged multi-port scanner covering standard HTTP, HTTPS, Web Management, TR-069, Winbox, and Telnet ports.
    """
    arp_info = arp_table.get(ip) if arp_table else None
    open_ports = []

    # Stage 1: Ultra-fast TCP connect probe on primary ports (80, 8080, 23, 8291) with 300ms timeout
    primary_candidates = [80, 8080, 23, 8291]
    for p in primary_candidates:
        if check_port(ip, p, timeout=0.3):
            open_ports.append(p)

    # If no primary port is open AND host is not in ARP cache, it is offline / dead IP -> Early exit!
    if not open_ports and not arp_info:
        return None

    # Stage 2: If host is alive or in ARP, scan remaining secondary ports
    secondary_ports = [443, 8081, 8000, 8443, 7547, 8728, 8888, 22]
    for p in secondary_ports:
        if check_port(ip, p, timeout=0.3):
            open_ports.append(p)

    if open_ports:
        return identify_ont(ip, open_ports, arp_info)
    
    # If no HTTP port open but present in active ARP cache with known vendor
    if arp_info and arp_info.get("vendor_hint"):
        gen = GenericAdapter(ip=ip, port=80, timeout=2)
        v_name = f"{arp_info['vendor_hint']} (Port Web Tertutup)"
        return {
            "ip": ip,
            "port": 80,
            "open_ports": [],
            "vendor": v_name,
            "device_type": get_device_category(v_name),
            "adapter": gen,
            "mac": arp_info.get("mac"),
        }

    return None

def discover_upstream_routing_hops(max_hops: int = 4, target: str = '8.8.8.8') -> List[Dict[str, Any]]:
    """
    Trace network hops above the current local modem/WAN to discover MikroTik, Core ISP, and edge gateways.
    Fast non-blocking with strict timeout for Termux / Linux.
    """
    hops = []
    seen = set()
    for ttl in range(1, max_hops + 1):
        try:
            # Use integer timeout -W 1 for Android Toybox / Linux iputils compatibility + python timeout 0.8s
            cmd = ['ping', '-c', '1', '-t', str(ttl), '-W', '1', target]
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=0.8)
            break
        except subprocess.TimeoutExpired:
            continue
        except subprocess.CalledProcessError as e:
            m = re.search(r'From\s+([0-9\.]+)', e.output)
            if m:
                ip = m.group(1)
                if ip not in seen and not ip.startswith('127.'):
                    seen.add(ip)
                    hops.append({'hop': ttl, 'gateway': ip})
        except Exception:
            pass
    return hops

def get_all_detected_gateways_and_subnets(wan_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Discover all available network interfaces, active IP pools, upstream gateways, and ISP distribution classes.
    """
    results = []
    seen_subnets = set()

    # 1. Local Network Interfaces & Routing Gateways
    try:
        routes = json.loads(subprocess.check_output(['ip', '-j', 'route'], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2))
    except Exception:
        routes = []

    try:
        addrs = json.loads(subprocess.check_output(['ip', '-j', 'addr'], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2))
    except Exception:
        addrs = []

    iface_gw = {}
    for r in routes:
        if r.get('dst') == 'default' and r.get('gateway') and r.get('dev'):
            iface_gw[r['dev']] = r['gateway']

    for iface in addrs:
        if iface.get('operstate') == 'UP' and iface.get('ifname') != 'lo':
            dev_name = iface.get('ifname')
            for addr in iface.get('addr_info', []):
                if addr.get('family') == 'inet':
                    ip = addr.get('local')
                    prefix = addr.get('prefixlen')
                    net = str(ipaddress.IPv4Network(f'{ip}/{prefix}', strict=False))
                    gw = iface_gw.get(dev_name) or (ip.rsplit('.', 1)[0] + '.1')
                    if net not in seen_subnets:
                        seen_subnets.add(net)
                        results.append({
                            'source': f'LAN PC Lokal ({dev_name})',
                            'subnet': net,
                            'cidr': f'/{prefix}',
                            'gateway': gw,
                            'ip_local': ip,
                            'hosts': ipaddress.IPv4Network(net).num_addresses - 2,
                            'status': 'Aktif Terhubung',
                            'type': 'LAN'
                        })

    # 2. WAN Gateway & Distribution Subnets from Connected Modem/Router
    if wan_info:
        wan_ip = wan_info.get('wan_ip')
        wan_gw = wan_info.get('wan_gateway') or (wan_ip.rsplit('.', 1)[0] + '.1' if wan_ip else None)
        if wan_gw or wan_ip:
            base_ip = wan_gw or wan_ip
            net24 = str(ipaddress.IPv4Network(f'{base_ip}/24', strict=False))
            if net24 not in seen_subnets:
                seen_subnets.add(net24)
                results.append({
                    'source': 'Subnet Gateway WAN / Distribusi',
                    'subnet': net24,
                    'cidr': '/24',
                    'gateway': wan_gw,
                    'ip_local': wan_ip,
                    'hosts': 254,
                    'status': 'Aktif Terdeteksi',
                    'type': 'WAN'
                })

    # 3. Upstream Routing Gateways Discovery Above WAN (Hop 1, Hop 2 MikroTik, Hop 3 Core ISP)
    hops = discover_upstream_routing_hops(max_hops=5)
    for h in hops:
        gw_ip = h['gateway']
        hop_num = h['hop']
        net24 = str(ipaddress.IPv4Network(f'{gw_ip}/24', strict=False))
        
        if hop_num == 1:
            label = f'Hop 1: Gateway Modem Lokal ({gw_ip})'
        elif hop_num == 2:
            label = f'Hop 2: Gateway MikroTik / OLT di atas WAN ({gw_ip})'
        elif hop_num == 3:
            label = f'Hop 3: Gateway Core Router ISP ({gw_ip})'
        else:
            label = f'Hop {hop_num}: Gateway Routing ISP Upstream ({gw_ip})'

        if net24 not in seen_subnets:
            seen_subnets.add(net24)
            results.append({
                'source': label,
                'subnet': net24,
                'cidr': '/24',
                'gateway': gw_ip,
                'ip_local': '-',
                'hosts': 254,
                'status': 'Aktif Online',
                'type': f'HOP_{hop_num}'
            })


    # 4. Configured IP Addresses & Interfaces directly from MikroTik RouterOS
    if wan_info and wan_info.get("mikrotik_ip_addresses"):
        for addr in wan_info["mikrotik_ip_addresses"]:
            raw_addr = addr.get("address")
            if raw_addr and "/" in raw_addr:
                try:
                    iface_obj = ipaddress.IPv4Interface(raw_addr)
                    net = str(iface_obj.network)
                    if net not in seen_subnets:
                        seen_subnets.add(net)
                        comment = addr.get("comment") or addr.get("interface") or "MikroTik Interface"
                        results.append({
                            "source": f"MikroTik: {addr.get('interface')} ({comment})",
                            "subnet": net,
                            "cidr": f"/{iface_obj.network.prefixlen}",
                            "gateway": str(iface_obj.ip),
                            "ip_local": str(iface_obj.ip),
                            "hosts": iface_obj.network.num_addresses - 2,
                            "status": "Aktif di MikroTik",
                            "type": "MIKROTIK_ADDR"
                        })
                except Exception:
                    pass

    # 5. Configured IP Pools directly from MikroTik RouterOS
    if wan_info and wan_info.get("mikrotik_ip_pools"):
        for pool in wan_info["mikrotik_ip_pools"]:
            ranges = pool.get("ranges", "")
            if "-" in ranges:
                start_ip = ranges.split("-")[0].strip()
                try:
                    iface_obj = ipaddress.IPv4Interface(f"{start_ip}/24")
                    net = str(iface_obj.network)
                    if net not in seen_subnets:
                        seen_subnets.add(net)
                        results.append({
                            "source": f"MikroTik Pool: {pool.get('name')} ({ranges})",
                            "subnet": net,
                            "cidr": "/24",
                            "gateway": str(iface_obj.network.network_address + 1),
                            "ip_local": ranges,
                            "hosts": 254,
                            "status": "Pool MikroTik",
                            "type": "MIKROTIK_POOL"
                        })
                except Exception:
                    pass

    return results

def parse_target_network_input(user_input_str: str, detected_subnets: List[Dict[str, Any]] = None, default_gw: str = "192.168.1.1") -> List[Dict[str, str]]:
    """
    Parse any user network input (table index, multiple indexes, gateway IP with CIDR, prefix /20, or raw IP).
    Examples:
      - '20.20.20.1/24' -> subnet: 20.20.20.0/24, gateway: 20.20.20.1
      - '20.20.20.1' -> subnet: 20.20.20.0/24, gateway: 20.20.20.1
      - '20.20.20.1/20' -> subnet: 20.20.16.0/20, gateway: 20.20.20.1
      - '1,2' or '1,3' -> chooses indexes from detected_subnets
      - 'A' -> chooses all detected subnets
      - '10.10.10.1/24, 20.20.20.1/24, 41.33.55.1/24' -> parses each into distinct subnets
    """
    results = []
    clean = user_input_str.strip()
    if not clean:
        if detected_subnets:
            return [{'subnet': detected_subnets[0]['subnet'], 'gateway': detected_subnets[0].get('gateway')}]
        return [{'subnet': '192.168.1.0/24', 'gateway': default_gw}]

    if clean.lower() in ['a', 'all', 'semua'] and detected_subnets:
        for s in detected_subnets:
            results.append({'subnet': s['subnet'], 'gateway': s.get('gateway')})
        return results

    tokens = [t.strip() for t in clean.replace(' ', ',').split(',') if t.strip()]

    for token in tokens:
        # Check if table index (1, 2, 3...)
        if token.isdigit() and detected_subnets and 1 <= int(token) <= len(detected_subnets):
            entry = detected_subnets[int(token) - 1]
            results.append({'subnet': entry['subnet'], 'gateway': entry.get('gateway')})
            continue

        # Check if prefix only (/20, /24, /22, /16)
        if token.startswith('/') and token[1:].isdigit():
            pfx = token[1:]
            base_gw = default_gw
            if detected_subnets and len(detected_subnets) > 0:
                base_gw = detected_subnets[0].get('gateway') or default_gw
            try:
                iface = ipaddress.IPv4Interface(f'{base_gw}/{pfx}')
                results.append({'subnet': str(iface.network), 'gateway': str(iface.ip)})
            except Exception:
                pass
            continue

        # Check if IP with prefix e.g. 20.20.20.1/24 or 20.20.20.0/24 or 20.20.20.1/20
        if '/' in token:
            try:
                iface = ipaddress.IPv4Interface(token)
                results.append({'subnet': str(iface.network), 'gateway': str(iface.ip)})
                continue
            except Exception:
                pass

        # Check if single IP e.g. 20.20.20.1 or 41.33.55.1
        try:
            ip_obj = ipaddress.IPv4Address(token)
            iface = ipaddress.IPv4Interface(f'{token}/24')
            results.append({'subnet': str(iface.network), 'gateway': str(ip_obj)})
            continue
        except Exception:
            pass

    # Fallback if parsing failed
    if not results:
        if detected_subnets:
            results.append({'subnet': detected_subnets[0]['subnet'], 'gateway': detected_subnets[0].get('gateway')})
        else:
            results.append({'subnet': '192.168.1.0/24', 'gateway': default_gw})

    # Deduplicate by subnet
    seen = set()
    dedup = []
    for r in results:
        if r['subnet'] not in seen:
            seen.add(r['subnet'])
            dedup.append(r)
    return dedup

def _check_kw(text: str, keywords: List[str]) -> bool:
    for k in keywords:
        if len(k) <= 4:
            if re.search(rf"\b{re.escape(k)}\b", text, re.IGNORECASE):
                return True
        else:
            if k.lower() in text.lower():
                return True
    return False

def identify_ont(ip: str, open_ports: List[int], arp_info: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
    """
    Fast unified fingerprinting for:
    - Modem LAN (1-Port EPON/GPON/XPON Bridge ONUs: Huawei HG8310M, ZTE F401, VSOL V2801, HSGQ, HIOSO, BDCOM, etc.)
    - Modem ONT (Multi-Port & Wi-Fi: ZTE GM220-S/F609/F670, Huawei HG8245/EG8145, Fiberhome AN5506-04, etc.)
    - Router Wi-Fi / AP (Tenda, TP-Link, Totolink, Mercusys, etc.)
    - Gateway / MikroTik RouterOS
    - Klien Hotspot
    """
    primary_port = 80 if 80 in open_ports else (8080 if 8080 in open_ports else (443 if 443 in open_ports else open_ports[0]))
    mac_addr = arp_info.get("mac") if arp_info else None
    mac_hint = (arp_info.get("vendor_hint") or "").lower() if arp_info else ""
    
    # 1. Direct check for Winbox / MikroTik API
    if 8291 in open_ports or 8728 in open_ports:
        ad = MikrotikAdapter(ip=ip, port=primary_port, timeout=2)
        return {
            "ip": ip,
            "port": primary_port,
            "open_ports": open_ports,
            "vendor": ad.vendor_name,
            "device_type": "Gateway / MikroTik",
            "adapter": ad,
            "mac": mac_addr,
        }

    # 2. Single HTTP probe to inspect headers and body
    r_text = ""
    r_url = ""
    r_headers = {}
    r_title = ""
    is_timed_out = False
    
    try:
        import requests
        r = requests.get(f"http://{ip}:{primary_port}/", timeout=2.5, allow_redirects=True)
        r_text = r.text.lower()
        r_url = r.url.lower()
        r_headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}
        # Extract HTML <title>
        title_m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
        if title_m:
            r_title = title_m.group(1).strip().lower()
    except Exception:
        # Fallback probe on /start.ghtml
        try:
            r = requests.get(f"http://{ip}:{primary_port}/start.ghtml", timeout=2.0)
            r_text = r.text.lower()
            r_url = r.url.lower()
            r_headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            title_m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
            if title_m:
                r_title = title_m.group(1).strip().lower()
        except Exception:
            pass

    combined = f"{r_text} {r_url} {r_title} {r_headers.get('server', '')} {r_headers.get('www-authenticate', '')} {mac_hint}"

    # 3. Check if explicit MikroTik Hotspot Captive Portal Interception
    if any(k in r_text for k in ["$(link-login-only)", "mikrotik hotspot", "hotspot login"]) and "mikrotik" in combined:
        gen = GenericAdapter(ip=ip, port=primary_port, timeout=2)
        return {
            "ip": ip,
            "port": primary_port,
            "open_ports": open_ports,
            "vendor": "Klien Hotspot (Terintersepsi MikroTik)",
            "device_type": "Klien Hotspot",
            "adapter": gen,
            "mac": mac_addr,
        }

    # 4. Accurate Fingerprinting

    # --- A. MODEM LAN / 1-PORT EPON/GPON/XPON BRIDGE ONU ---
    if _check_kw(combined, ["hg8310", "hg8010", "eg8010"]):
        ad = HuaweiAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Huawei HG8310M/HG8010H (Modem LAN 1-Port)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f401", "f601", "zxhn f401", "zxhn f601"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE F401/F601 (Modem LAN 1-Port)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["an5506-01", "an5506-01a", "an5506-01b"]):
        ad = FiberhomeAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Fiberhome AN5506-01 (Modem LAN 1-Port)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["v2801", "v2801sg", "v2801se", "v2801rd", "fd511", "fd511g", "fd511gw"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "VSOL / C-Data V2801 (Modem LAN 1-Port)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["hsgq", "hsqg", "e04", "g01"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "HSGQ 1-Port EPON/GPON ONU (Modem LAN)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["hioso", "ha7200", "ha7100"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "HIOSO 1-Port EPON ONU (Modem LAN)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["bdcom", "gp1701", "ep101"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "BDCOM 1-Port EPON/GPON ONU (Modem LAN)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["epon onu", "gpon onu", "xpon onu", "1ge onu", "1fe onu", "onu bridge", "1-port onu"]) and not any(k in combined for k in ["f609", "f660", "f670", "gm220", "hg8245", "eg8145", "an5506-04"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "EPON/GPON 1-Port ONU Bridge (Modem LAN)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem LAN (ONU 1-Port)", "adapter": ad, "mac": mac_addr}

    # --- B. MODEM ONT (MULTI-PORT / WI-FI GPON / XPON) ---
    if _check_kw(combined, ["gm220", "gm220-s"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE GM220-S (XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f663nv3a"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE ZXHN F663NV3A (XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f663nv9"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE ZXHN F663NV9 (XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f663", "f663n"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE ZXHN F663N (XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f477", "zxhn f477", "f477v2", "f470", "zxhn f470"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE ZXHN F477/F470 (GPON/EPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f670", "f670l"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE F670L (Dual-Band GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f609", "zxhn f609"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE F609 (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["f660", "zxhn f660"]):
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE F660 (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["frm_logintoken", "net_wlan_essid_t.gch", "getpage.gch", "zte corporation", "zte-webs", "zte corp", "flogin"]) or "zte" in r_headers.get("server", "") or "zte" in mac_hint:
        ad = ZTEAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "ZTE Corporation (GPON/XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if "boa" in r_headers.get("server", "") and not _check_kw(combined, ["huawei", "fiberhome", "zte"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Realtek / VSOL / C-Data (XPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["eg8145", "eg8141"]):
        ad = HuaweiAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Huawei EG8145/EG8141 (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["hg8245", "hg8247", "hg8546", "echolife"]):
        ad = HuaweiAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Huawei EchoLife HG8245 (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["hw_login", "x_hw_", "getfeatureinfo.asp", "huawei-webs"]) or "huawei" in combined:
        ad = HuaweiAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Huawei Technologies (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["an5506-04", "an5506-02", "hg680", "fh_login", "fiberhome"]):
        ad = FiberhomeAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Fiberhome AN5506 (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["vsol", "c-data", "cdata", "v2804", "v2802", "fd504"]):
        ad = VSOLAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "VSOL / C-Data (XPON/EPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Modem ONT", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["nokia", "alcatel", "g-240w", "g-2425", "i-240w"]) or "nokia" in mac_hint or "alcatel" in mac_hint:
        gen = GenericAdapter(ip=ip, port=primary_port, timeout=2)
        gen.vendor_name = "Nokia / Alcatel-Lucent (GPON ONT)"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": gen.vendor_name, "device_type": "Modem ONT", "adapter": gen, "mac": mac_addr}

    # --- C. ROUTER WI-FI / AP (LAN / SOHO) ---
    if _check_kw(combined, ["tenda wireless router", "reasyui", "b28n.js", "tenda"]) or "tenda" in r_headers.get("server", "") or "tenda" in mac_hint:
        ad = TendaAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "Tenda Router Wi-Fi / AP"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Router Wi-Fi / AP", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["tp-link", "tplink", "wr840", "wr844", "wr841", "archer", "/userrpm/"]) or "tp-link" in r_headers.get("server", "") or "tp-link" in mac_hint:
        ad = TPLinkAdapter(ip=ip, port=primary_port, timeout=3)
        ad.vendor_name = "TP-Link Router Wi-Fi / AP"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Router Wi-Fi / AP", "adapter": ad, "mac": mac_addr}

    if _check_kw(combined, ["totolink", "n200re", "n300rt", "a720r"]) or "totolink" in mac_hint:
        gen = GenericAdapter(ip=ip, port=primary_port, timeout=3)
        gen.vendor_name = "Totolink Router Wi-Fi / AP"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": gen.vendor_name, "device_type": "Router Wi-Fi / AP", "adapter": gen, "mac": mac_addr}

    if _check_kw(combined, ["mercusys", "mw301r", "mw305r", "ac12"]) or "mercusys" in mac_hint:
        gen = GenericAdapter(ip=ip, port=primary_port, timeout=3)
        gen.vendor_name = "Mercusys Router Wi-Fi / AP"
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": gen.vendor_name, "device_type": "Router Wi-Fi / AP", "adapter": gen, "mac": mac_addr}

    if _check_kw(combined, ["mikrotik", "routeros", "webfig", "winbox"]):
        ad = MikrotikAdapter(ip=ip, port=primary_port, timeout=3)
        return {"ip": ip, "port": primary_port, "open_ports": open_ports, "vendor": ad.vendor_name, "device_type": "Gateway / MikroTik", "adapter": ad, "mac": mac_addr}

    # 5. Telnet-only fallback: port 23 open, no HTTP matched → use TelnetAdapter
    if 23 in open_ports and not any(p in open_ports for p in [80, 8080, 443]):
        ad = TelnetAdapter(ip=ip, port=23, timeout=4)
        if ad.detect():
            return {
                "ip": ip,
                "port": 23,
                "open_ports": open_ports,
                "vendor": ad.vendor_name,
                "device_type": "Modem ONT / Router (Telnet Only)",
                "adapter": ad,
                "mac": mac_addr,
            }

    # 6. MAC OUI & Generic Fallback
    vendor_fallback = "Perangkat Jaringan (Generic)"
    if arp_info and arp_info.get("vendor_hint"):
        vendor_fallback = f"{arp_info['vendor_hint']} (via MAC OUI)"
    device_type = get_device_category(vendor_fallback)

    gen = GenericAdapter(ip=ip, port=primary_port, timeout=2)
    return {
        "ip": ip,
        "port": primary_port,
        "open_ports": open_ports,
        "vendor": vendor_fallback,
        "device_type": device_type,
        "adapter": gen,
        "mac": mac_addr,
    }



def scan_network(cidr: str, max_threads: int = 100, callback = None) -> List[Dict[str, Any]]:
    """
    Scan a CIDR network range for active ONTs and Routers with multi-port detection.
    """
    network = ipaddress.IPv4Network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    
    found_devices = []
    total = len(hosts)
    completed = 0

    arp_table = get_arp_table()

    # Scale concurrency for large subnets
    threads = max_threads
    if total > 2000:
        threads = 200
    elif total > 500:
        threads = 120

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_host, ip, arp_table): ip for ip in hosts}
        for future in as_completed(futures):
            completed += 1
            ip = futures[future]
            try:
                device = future.result()
                if device:
                    found_devices.append(device)
                    if callback:
                        callback(completed, total, device)
                else:
                    if callback:
                        callback(completed, total, None)
            except Exception:
                if callback:
                    callback(completed, total, None)

    return sorted(found_devices, key=lambda d: ipaddress.IPv4Address(d["ip"]))
