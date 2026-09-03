import re
import socket
import requests
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum

class VendorEnum(str, Enum):
    ZTE = "ZTE Corporation"
    HUAWEI = "Huawei Technologies"
    REALTEK_BOA = "Realtek BoA OEM (VSOL/C-Data/XPON)"
    FIBERHOME = "Fiberhome"
    NOKIA = "Nokia / Alcatel-Lucent"
    TENDA = "Tenda Router Wi-Fi / AP"
    TPLINK = "TP-Link Router Wi-Fi / AP"
    TOTOLINK = "Totolink Router Wi-Fi / AP"
    MERCUSYS = "Mercusys Router Wi-Fi / AP"
    MIKROTIK = "MikroTik RouterOS"
    GENERIC = "Generic / XPON ONT"

class FingerprintResult:
    def __init__(
        self,
        ip: str,
        vendor: VendorEnum,
        model: str,
        driver_name: str,
        adapter_class: Any,
        primary_port: int,
        open_ports: List[int],
        server_header: str = "",
        web_form_type: str = "",
        mac: Optional[str] = None,
        raw_banner: str = ""
    ):
        self.ip = ip
        self.vendor = vendor
        self.model = model
        self.driver_name = driver_name
        self.adapter_class = adapter_class
        self.primary_port = primary_port
        self.open_ports = open_ports
        self.server_header = server_header
        self.web_form_type = web_form_type
        self.mac = mac
        self.raw_banner = raw_banner

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "vendor": self.vendor.value,
            "model": self.model,
            "driver_name": self.driver_name,
            "primary_port": self.primary_port,
            "open_ports": self.open_ports,
            "server_header": self.server_header,
            "web_form_type": self.web_form_type,
            "mac": self.mac,
            "raw_banner": self.raw_banner,
        }

def probe_telnet_banner(ip: str, port: int = 23, timeout: float = 1.2) -> str:
    """Probe port 23 and return initial banner text."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.settimeout(0.5)
            try:
                data = s.recv(1024)
                return data.decode("latin-1", errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""

def detect_device_fingerprint(
    ip: str,
    open_ports: List[int],
    arp_info: Optional[Dict[str, Any]] = None
) -> FingerprintResult:
    """
    Unified signature and fingerprint detector:
    - 1x HTTP GET request (status, headers, body, redirects, cookies)
    - URL redirect & form action analysis (/getpage.gch, /boaform/admin/formLogin, /html/index.html, etc.)
    - Server header analysis (Mini web server, GoAhead-Webs, Boa/0.94, etc.)
    - Telnet banner analysis if port 23 is open
    """
    from adapters.zte import (
        ZTEAdapter,
        ZTEGM220Adapter,
        ZTEF663Adapter,
        ZTEF609Adapter,
        ZTEF670Adapter,
    )
    from adapters.huawei import (
        HuaweiAdapter,
        HuaweiHG8245Adapter,
        HuaweiEG8145Adapter,
    )
    from adapters.fiberhome import (
        FiberhomeAdapter,
        FiberhomeAN5506Adapter,
        FiberhomeHG680Adapter,
    )
    from adapters.vsol import (
        VSOLAdapter,
        VSOLV2801Adapter,
        VSOLV2802Adapter,
    )
    from adapters.tplink import (
        TPLinkAdapter,
        TPLinkXC220Adapter,
    )
    from adapters.tenda import (
        TendaAdapter,
        TendaHG9Adapter,
    )
    from adapters.realtek_boa import RealtekBoAAdapter
    from adapters.mikrotik import MikrotikAdapter
    from adapters.generic import GenericAdapter
    from adapters.telnet import TelnetAdapter

    primary_port = 80 if 80 in open_ports else (8080 if 8080 in open_ports else (443 if 443 in open_ports else (open_ports[0] if open_ports else 80)))
    mac_addr = arp_info.get("mac") if arp_info else None
    mac_hint = (arp_info.get("vendor_hint") or "").lower() if arp_info else ""

    # 1. MikroTik Winbox / API check
    if 8291 in open_ports or 8728 in open_ports:
        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.MIKROTIK,
            model="RouterBOARD / RouterOS",
            driver_name="MikrotikAdapter",
            adapter_class=MikrotikAdapter,
            primary_port=primary_port,
            open_ports=open_ports,
            mac=mac_addr
        )

    # 2. HTTP Probe (1 request)
    r_text = ""
    r_url = ""
    r_headers = {}
    r_server = ""
    r_title = ""

    if any(p in open_ports for p in [80, 8080, 8081, 8000, 8443, 443]):
        try:
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            })
            r = session.get(f"http://{ip}:{primary_port}/", timeout=1.2, allow_redirects=True)
            r_text = r.text.lower()
            r_url = r.url.lower()
            r_headers = {k.lower(): str(v).lower() for k, v in r.headers.items()}
            r_server = r_headers.get("server", "")
            title_m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
            if title_m:
                r_title = title_m.group(1).lower().strip()
        except Exception:
            pass

    # 3. Telnet banner probe if port 23 is open
    telnet_banner = ""
    if 23 in open_ports:
        telnet_banner = probe_telnet_banner(ip, port=23, timeout=0.8).lower()

    combined = f"{r_url} {r_server} {r_title} {r_text[:3000]} {telnet_banner} {mac_hint}"

    # --- A. ZTE / ZXIC DETECTOR ---
    # Signature: /getpage.gch, Frm_Logintoken, Mini web server, zfc_, gm220, f609, f670, f677, zx-f677, zxic
    if (
        "getpage.gch" in r_url
        or "frm_logintoken" in r_text
        or "zfc_" in r_text
        or "mini web server" in r_server
        or any(k in combined for k in ["zte", "zxic", "gm220", "f609", "f670", "f677", "zx-f677", "f660", "f663", "f477", "f470", "zxhn", "c0d0ff"])
    ):
        model_name = "ZTE GPON/XPON ONT"
        driver_name = "ZTEGM220Adapter"
        driver_cls = ZTEGM220Adapter

        if "gm220" in combined:
            model_name = "ZTE GM220-S GPON ONT"
            driver_name = "ZTEGM220Adapter"
            driver_cls = ZTEGM220Adapter
        elif "f663" in combined:
            model_name = "ZTE ZXHN F663 (XPON/GPON ONT)"
            driver_name = "ZTEF663Adapter"
            driver_cls = ZTEF663Adapter
        elif "f609" in combined or "f660" in combined or "f620" in combined:
            model_name = "ZTE ZXHN F609 GPON ONT"
            driver_name = "ZTEF609Adapter"
            driver_cls = ZTEF609Adapter
        elif "f670" in combined or "f672" in combined or "f677" in combined or "f477" in combined or "f470" in combined:
            model_name = "ZTE ZXHN F670L Dualband"
            driver_name = "ZTEF670Adapter"
            driver_cls = ZTEF670Adapter

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.ZTE,
            model=model_name,
            driver_name=driver_name,
            adapter_class=driver_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="getpage.gch (Token/Cookie)",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- B. HUAWEI DETECTOR ---
    # Signature: /html/index.html, hw_login, echolife, hg8245, eg8145
    if (
        "hw_login" in r_text
        or "x_hw_" in r_text
        or "getfeatureinfo.asp" in r_text
        or "huawei-webs" in r_server
        or any(k in combined for k in ["huawei", "echolife", "hg8245", "hg8546", "eg8145", "eg8141", "hg8310"])
    ):
        model_name = "Huawei EchoLife GPON ONT"
        ad_cls = HuaweiAdapter
        if "eg8145" in combined or "eg8141" in combined:
            model_name = "Huawei EG8145/EG8141 GPON ONT"
            ad_cls = HuaweiEG8145Adapter
        elif "hg8245" in combined or "hg8546" in combined:
            model_name = "Huawei HG8245/HG8546 GPON ONT"
            ad_cls = HuaweiHG8245Adapter

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.HUAWEI,
            model=model_name,
            driver_name=ad_cls.__name__,
            adapter_class=ad_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="ASP / Huawei BBSP",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- C. REALTEK BOA OEM & VSOL ---
    # Signature: /boaform/admin/formLogin, Boa/0.94, vsol, cdata, xpon onu, fd511, v2801
    if (
        "boaform" in r_text
        or "boaform" in r_url
        or "boa/" in r_server
        or any(k in combined for k in ["vsol", "c-data", "cdata", "v2801", "v2802", "v2804", "fd511", "xpon onu", "epon onu", "syrotech", "netlink"])
    ):
        model_name = "Realtek BoA XPON/EPON ONU"
        ad_cls = RealtekBoAAdapter
        if "v2802" in combined or "v2804" in combined:
            model_name = "VSOL V2802/V2804 Dualband ONT"
            ad_cls = VSOLV2802Adapter
        elif "vsol" in combined or "v2801" in combined:
            model_name = "VSOL V2801/XPON ONU"
            ad_cls = VSOLV2801Adapter
        elif "c-data" in combined or "cdata" in combined or "fd511" in combined:
            model_name = "C-Data FD511/XPON ONU"
        elif "syrotech" in combined:
            model_name = "Syrotech XPON ONU"
        elif "netlink" in combined:
            model_name = "Netlink XPON ONU"

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.REALTEK_BOA if ad_cls == RealtekBoAAdapter else VendorEnum.VSOL,
            model=model_name,
            driver_name=ad_cls.__name__,
            adapter_class=ad_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="boaform/admin/formLogin",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- D. FIBERHOME DETECTOR ---
    # Signature: an5506, fh_login, hg680, hg6243c, fiberhome
    if (
        "fh_login" in r_text
        or any(k in combined for k in ["fiberhome", "an5506", "hg680", "hg6243c"])
    ):
        model_name = "Fiberhome AN5506 GPON ONT"
        ad_cls = FiberhomeAN5506Adapter
        if "hg680" in combined or "hg6243c" in combined:
            model_name = "Fiberhome HG680 GPON ONT"
            ad_cls = FiberhomeHG680Adapter

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.FIBERHOME,
            model=model_name,
            driver_name=ad_cls.__name__,
            adapter_class=ad_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="fh_login / Web",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- E. NOKIA / ALCATEL-LUCENT DETECTOR ---
    if any(k in combined for k in ["nokia", "alcatel", "g-240w", "g-2425", "i-240w"]):
        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.NOKIA,
            model="Nokia / Alcatel-Lucent GPON ONT",
            driver_name="GenericAdapter (Nokia)",
            adapter_class=GenericAdapter,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- F. TENDA SOHO ROUTER / AP DETECTOR ---
    if (
        "reasyui" in r_text
        or "b28n.js" in r_text
        or "goform/gethomepageinfo" in r_text
        or any(k in combined for k in ["tenda wireless router", "tenda technology", "tenda", "n301", "f3", "ac10", "hg9", "hg6", "hg3"])
    ):
        model_name = "Tenda Router Wi-Fi / AP"
        ad_cls = TendaAdapter
        if any(k in combined for k in ["hg9", "hg6", "hg3"]):
            model_name = "Tenda HG9 Dualband GPON ONT"
            ad_cls = TendaHG9Adapter

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.TENDA,
            model=model_name,
            driver_name=ad_cls.__name__,
            adapter_class=ad_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="goform/loginAuth",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- G. TP-LINK ROUTER / AP DETECTOR ---
    if (
        "userrpm" in r_text
        or "userrpm" in r_url
        or any(k in combined for k in ["tp-link", "tplink", "wr840", "wr844", "wr841", "archer", "xc220", "tx-6610"])
    ):
        model_name = "TP-Link Router Wi-Fi / AP"
        ad_cls = TPLinkAdapter
        if "xc220" in combined or "tx-6610" in combined:
            model_name = "TP-Link XC220 Dualband XPON ONT"
            ad_cls = TPLinkXC220Adapter

        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.TPLINK,
            model=model_name,
            driver_name=ad_cls.__name__,
            adapter_class=ad_cls,
            primary_port=primary_port,
            open_ports=open_ports,
            server_header=r_server,
            web_form_type="userRpm/LoginRpm.htm",
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- H. TOTOLINK / MERCUSYS DETECTOR ---
    if any(k in combined for k in ["totolink", "n200re", "n300rt", "a720r"]):
        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.TOTOLINK,
            model="Totolink Router Wi-Fi / AP",
            driver_name="GenericAdapter",
            adapter_class=GenericAdapter,
            primary_port=primary_port,
            open_ports=open_ports,
            mac=mac_addr
        )

    if any(k in combined for k in ["mercusys", "mw301r", "mw305r", "ac12"]):
        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.MERCUSYS,
            model="Mercusys Router Wi-Fi / AP",
            driver_name="GenericAdapter",
            adapter_class=GenericAdapter,
            primary_port=primary_port,
            open_ports=open_ports,
            mac=mac_addr
        )

    # --- I. TELNET ONLY FALLBACK ---
    if 23 in open_ports and not any(p in open_ports for p in [80, 8080, 443]):
        return FingerprintResult(
            ip=ip,
            vendor=VendorEnum.GENERIC,
            model="Modem ONT / Router (Telnet Only)",
            driver_name="TelnetAdapter",
            adapter_class=TelnetAdapter,
            primary_port=23,
            open_ports=open_ports,
            mac=mac_addr,
            raw_banner=telnet_banner
        )

    # --- J. GENERIC FALLBACK ---
    return FingerprintResult(
        ip=ip,
        vendor=VendorEnum.GENERIC,
        model=f"{arp_info.get('vendor_hint', 'Generic Device')} (Port Web)",
        driver_name="GenericAdapter",
        adapter_class=GenericAdapter,
        primary_port=primary_port,
        open_ports=open_ports,
        server_header=r_server,
        mac=mac_addr
    )
