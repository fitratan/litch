import os
import time
import json
import csv
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Optional
from credentials import get_credentials, get_vendor_prioritized_credentials, save_cached_credential

def ensure_authenticated_device(
    device: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None,
    require_admin: bool = False
) -> Tuple[bool, Optional[str], Optional[str], Any]:
    """
    Ensure the ONT adapter is authenticated cleanly:
    - Uses existing authenticated session if active (and meets admin requirement)
    - Prioritizes administrator / superadmin credentials over standard user accounts
    - Automatically falls back to ZTEAdapter if GenericAdapter was initially assigned
    - Caches successful credentials for subsequent operations
    """
    ip = device["ip"]
    adapter = device.get("adapter")
    vendor = device.get("vendor", "")
    port = device.get("port", 80)

    if adapter is None:
        v_upper = vendor.upper()
        if "GM220" in v_upper:
            from adapters.zte_gm220 import ZTEGM220Adapter
            adapter = ZTEGM220Adapter(ip, port, timeout=3)
        elif "F663" in v_upper:
            from adapters.zte_f663 import ZTEF663Adapter
            adapter = ZTEF663Adapter(ip, port, timeout=3)
        elif "F609" in v_upper:
            from adapters.zte_f609 import ZTEF609Adapter
            adapter = ZTEF609Adapter(ip, port, timeout=3)
        elif "F670" in v_upper:
            from adapters.zte_f670 import ZTEF670Adapter
            adapter = ZTEF670Adapter(ip, port, timeout=3)
        elif "ZTE" in v_upper:
            from adapters.zte import ZTEAdapter
            adapter = ZTEAdapter(ip, port, timeout=3)
        elif "HUAWEI" in v_upper or "HG8245" in v_upper or "EG8145" in v_upper:
            from adapters.huawei import HuaweiAdapter
            adapter = HuaweiAdapter(ip, port, timeout=3)
        elif "FIBERHOME" in v_upper or "AN5506" in v_upper or "HG680" in v_upper:
            from adapters.fiberhome import FiberhomeAdapter
            adapter = FiberhomeAdapter(ip, port, timeout=3)
        elif "VSOL" in v_upper or "V2801" in v_upper or "V2802" in v_upper:
            from adapters.vsol import VSOLAdapter
            adapter = VSOLAdapter(ip, port, timeout=3)
        elif "TENDA" in v_upper or "N301" in v_upper or "F3" in v_upper or "HG9" in v_upper:
            from adapters.tenda import TendaAdapter
            adapter = TendaAdapter(ip, port, timeout=3)
        elif "TP-LINK" in v_upper or "TPLINK" in v_upper or "WR840" in v_upper or "XC220" in v_upper:
            from adapters.tplink import TPLinkAdapter
            adapter = TPLinkAdapter(ip, port, timeout=3)
        elif "MIKROTIK" in v_upper or "ROUTEROS" in v_upper:
            from adapters.mikrotik import MikrotikAdapter
            adapter = MikrotikAdapter(ip, port, timeout=3)
        elif 23 in device.get("open_ports", []):
            from adapters.telnet import TelnetAdapter
            adapter = TelnetAdapter(ip, 23, timeout=3)
        else:
            from adapters.generic import GenericAdapter
            adapter = GenericAdapter(ip, port, timeout=3)
        device["adapter"] = adapter

    curr_user = getattr(adapter, "authenticated_user", None)
    if adapter and curr_user:
        is_low_priv = curr_user.lower() in ["nara", "user", "useradmin", "guest"]
        if not (require_admin and is_low_priv):
            return True, adapter.authenticated_user, adapter.authenticated_password, adapter

    # Build prioritized credential candidates
    v_creds = get_vendor_prioritized_credentials(device.get("vendor", ""), ip_or_mac=ip)
    if custom_creds:
        combined = []
        for c in custom_creds + v_creds:
            if c not in combined:
                combined.append(c)
        raw_list = combined[:35]
    else:
        raw_list = v_creds[:35]

    def credential_role_score(cred):
        u, p = cred
        u_l = u.lower().strip()
        if u_l in ["admin", "telecomadmin", "superadmin", "root"]:
            return 100
        elif "admin" in u_l or "root" in u_l or "support" in u_l:
            return 80
        elif u_l in ["nara", "user", "useradmin", "guest"]:
            return 10
        return 30

    creds_list = sorted(raw_list, key=credential_role_score, reverse=True)

    # 1. If GenericAdapter was assigned, test ZTEAdapter first (95%+ of ONTs on ISP subnet are ZTE)
    if adapter and adapter.__class__.__name__ == "GenericAdapter":
        try:
            from adapters.zte import ZTEAdapter
            zte_ad = ZTEAdapter(ip, device.get("port", 80), timeout=2.5)
            for u, p in creds_list[:4]:
                ok, msg = zte_ad.login(u, p)
                if ok:
                    device["adapter"] = zte_ad
                    device["driver_name"] = "ZTEAdapter"
                    device["vendor"] = "ZTE GM220-S (XPON ONT)"
                    save_cached_credential(ip, u, p)
                    if device.get("mac"):
                        save_cached_credential(device["mac"], u, p)
                    return True, u, p, zte_ad
        except Exception:
            pass

    # 2. Try with assigned adapter
    consecutive_errs = 0
    for u, p in creds_list:
        try:
            ok, msg = adapter.login(u, p)
            if ok:
                save_cached_credential(ip, u, p)
                if device.get("mac"):
                    save_cached_credential(device["mac"], u, p)
                return True, u, p, adapter
            
            msg_l = str(msg).lower()
            if "terkunci" in msg_l or "locked" in msg_l or "rate-limit" in msg_l:
                break
            if any(err in msg_l for err in ["refused", "no route", "host unreachable", "timeout", "timed out", "connection error", "reset by peer", "failed to establish"]):
                consecutive_errs += 1
                if consecutive_errs >= 2:
                    break
        except Exception:
            pass

    return False, None, None, adapter

def process_single_ont(
    device: Dict[str, Any],
    wan_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Authenticate and configure WAN on a single ONT.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "wan_updated": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used
    result["message"] = f"Logged in as '{user_used}'"

    # Configure WAN
    if wan_config:
        target_wan = dict(wan_config)
        last_octet = ip.split(".")[-1]
        if "{ip_last}" in target_wan.get("pppoe_username", ""):
            target_wan["pppoe_username"] = target_wan["pppoe_username"].replace("{ip_last}", last_octet)

        try:
            wan_success, wan_msg = adapter.configure_wan(target_wan)
        except Exception as e:
            wan_success, wan_msg = False, f"Failed to configure WAN: {str(e)}"

        result["wan_updated"] = wan_success
        result["message"] = wan_msg

    return result

def run_batch_provisioning(
    devices: List[Dict[str, Any]],
    wan_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 25,
    callback = None
) -> List[Dict[str, Any]]:
    """
    Run batch WAN update across all given ONTs concurrently.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont, dev, wan_config, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def process_single_ont_password_change(
    device: Dict[str, Any],
    new_password: str,
    target_username: str = "admin",
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Authenticate and change admin/user password on a single ONT.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "password_changed": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds, require_admin=True)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

    chg_success, chg_msg = adapter.change_password(new_password, username=target_username)
    result["password_changed"] = chg_success
    result["message"] = chg_msg
    if chg_success:
        save_cached_credential(ip, target_username, new_password)
        if device.get("mac"):
            save_cached_credential(device["mac"], target_username, new_password)

    return result

def run_batch_password_change(
    devices: List[Dict[str, Any]],
    new_password: str,
    target_username: str = "admin",
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback = None
) -> List[Dict[str, Any]]:
    """
    Run batch password change across all given ONTs concurrently.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont_password_change, dev, new_password, target_username, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def inspect_single_device(
    device: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Multi-Protocol ONT Inspection (Web -> Telnet Fallback):
    - Authenticates using vendor-prioritized credentials and cached creds
    - Extracts PPPoE username, VLAN, WAN IP
    - Reads Optical Power (RX/TX Power in dBm)
    - Fallbacks to Telnet if Web HTTP fails
    """
    ip = device["ip"]
    adapter = device["adapter"]
    driver_name = device.get("driver_name") or adapter.__class__.__name__

    dev_data = dict(device)
    dev_data["driver_name"] = driver_name
    dev_data["login_success"] = False
    dev_data["username_used"] = None
    dev_data["password_used"] = None
    dev_data["wan_info"] = {}
    dev_data["pppoe_display"] = "-"
    dev_data["vlan_display"] = "-"
    dev_data["wan_ip_display"] = "-"
    dev_data["rx_power_display"] = "-"
    dev_data["optical_status"] = "N/A"

    if dev_data.get("device_type") == "Klien Hotspot":
        dev_data["pppoe_display"] = "Klien Hotspot (DHCP)"
        return dev_data

    if dev_data.get("device_type") == "Gateway / MikroTik":
        dev_data["pppoe_display"] = "Gateway MikroTik (Router Pusat)"
        dev_data["login_success"] = False
        dev_data["notes"] = "MikroTik Gateway (Dilewati / Login Dinonaktifkan)"
        return dev_data

    # Authenticate cleanly using unified ensure_authenticated_device
    ok, u_used, p_used, active_adapter = ensure_authenticated_device(device, custom_creds)
    if ok:
        dev_data["login_success"] = True
        dev_data["username_used"] = u_used
        dev_data["password_used"] = p_used
        dev_data["adapter"] = active_adapter
        dev_data["driver_name"] = active_adapter.__class__.__name__
        dev_data["vendor"] = device.get("vendor", dev_data.get("vendor", ""))
        adapter = active_adapter
    else:
        # Multi-Protocol Fallback: Telnet (Port 23) if Web failed
        if 23 in device.get("open_ports", []):
            try:
                from adapters.telnet import TelnetAdapter
                t_ad = TelnetAdapter(ip, 23, timeout=1.5)
                telnet_creds = [("root", "Zte521"), ("admin", "dnsolution"), ("superadmin", "suportadmin"), ("admin", "admin"), ("root", "root"), ("telecomadmin", "admintelecom")]
                for u, p in telnet_creds:
                    ok_t, msg_t = t_ad.login(u, p)
                    if ok_t:
                        dev_data["login_success"] = True
                        dev_data["username_used"] = f"{u} (Telnet)"
                        dev_data["password_used"] = p
                        dev_data["adapter"] = t_ad
                        adapter = t_ad
                        save_cached_credential(ip, u, p)
                        break
            except Exception:
                pass

    # Extract WAN & PPPoE Credentials
    if dev_data["login_success"]:
        try:
            wan = adapter.get_wan_info()
            dev_data["wan_info"] = wan
            user = wan.get("pppoe_user") or wan.get("username")
            pwd = wan.get("pppoe_password")
            sn = wan.get("gpon_sn")
            vlan = wan.get("vlan") or wan.get("vlan_id")
            wan_ip = wan.get("wan_ip") or wan.get("ip_address")

            dev_data["pppoe_user"] = user
            dev_data["pppoe_password"] = pwd
            dev_data["vlan"] = vlan
            dev_data["wan_ip"] = wan_ip
            dev_data["pppoe_display"] = user or "-"
            dev_data["pppoe_password_display"] = pwd or "-"
            dev_data["gpon_sn_display"] = sn or dev_data.get("mac") or "-"

            # Update exact Model and SN if parsed from ONT status pages
            if wan.get("model"):
                dev_data["vendor"] = wan["model"]
            if wan.get("gpon_sn"):
                dev_data["gpon_sn"] = wan["gpon_sn"]
                dev_data["gpon_sn_display"] = wan["gpon_sn"]

            if vlan:
                dev_data["vlan_display"] = str(vlan)
            if wan_ip:
                dev_data["wan_ip_display"] = str(wan_ip)
        except Exception:
            pass

        if hasattr(adapter, "get_wifi_info"):
            try:
                wifi = adapter.get_wifi_info()
                dev_data["wifi_info"] = wifi
                dev_data["wifi_ssid_display"] = wifi.get("ssid") or "-"
                dev_data["wifi_password_display"] = wifi.get("password") or "-"
            except Exception:
                pass

        if hasattr(adapter, "get_optical_power"):
            try:
                opt = adapter.get_optical_power()
                dev_data["optical_info"] = opt
                dev_data["rx_power_display"] = opt.get("rx_power_dbm") or "-"
            except Exception:
                pass

    return dev_data

def run_batch_device_inspection(
    devices: List[Dict[str, Any]],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback = None
) -> List[Dict[str, Any]]:
    """
    Fast concurrent authentication and WAN status extraction across all discovered ONTs.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(inspect_single_device, dev, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def process_single_ont_lan_config(
    device: Dict[str, Any],
    lan_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Authenticate and enable/disable LAN ports on a single ONT.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "lan_updated": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

    lan_ok, lan_msg = adapter.configure_lan_ports(lan_config)
    result["lan_updated"] = lan_ok
    result["message"] = lan_msg
    return result

def run_batch_lan_config(
    devices: List[Dict[str, Any]],
    lan_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback = None
) -> List[Dict[str, Any]]:
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont_lan_config, dev, lan_config, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def process_single_ont_wlan_config(
    device: Dict[str, Any],
    ssid_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Authenticate and configure Multi-SSID / Wi-Fi on a single ONT.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "wlan_updated": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

    # Build dynamic SSID name / password if pattern provided (e.g. {ip_last})
    target_cfg = dict(ssid_config)
    last_octet = ip.split(".")[-1]
    if "{ip_last}" in target_cfg.get("ssid_name", ""):
        target_cfg["ssid_name"] = target_cfg["ssid_name"].replace("{ip_last}", last_octet)
    if "{ip_last}" in target_cfg.get("password", ""):
        target_cfg["password"] = target_cfg["password"].replace("{ip_last}", last_octet)

    wlan_ok, wlan_msg = adapter.configure_wlan_ssid(target_cfg)
    result["wlan_updated"] = wlan_ok
    result["message"] = wlan_msg
    return result

def run_batch_wlan_config(
    devices: List[Dict[str, Any]],
    ssid_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback = None
) -> List[Dict[str, Any]]:
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont_wlan_config, dev, ssid_config, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def process_single_ont_reboot(
    device: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Login and reboot a single ONT/Router.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "rebooted": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

    ok_reb, msg_reb = adapter.reboot()
    result["rebooted"] = ok_reb
    result["message"] = msg_reb
    return result

def run_batch_reboot(
    devices: List[Dict[str, Any]],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback=None
) -> List[Dict[str, Any]]:
    """
    Reboot all selected ONTs concurrently.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont_reboot, dev, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

def process_single_ont_anti_reset(
    device: Dict[str, Any],
    lock_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None
) -> Dict[str, Any]:
    """
    Authenticate and apply Anti-Reset (Burn Config to ROM & Disable Reset Button) on a single ONT.
    """
    ip = device["ip"]
    result = {
        "ip": ip,
        "vendor": device.get("vendor", ""),
        "login_success": False,
        "username_used": None,
        "password_used": None,
        "anti_reset_locked": False,
        "message": "Authentication failed with all candidate credentials",
    }

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds, require_admin=True)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

    pwd_changed_msg = ""
    if lock_config.get("set_new_password") and lock_config.get("new_password"):
        target_u = lock_config.get("target_username") or user_used or "admin"
        new_p = lock_config.get("new_password")
        try:
            pwd_ok, pwd_msg = adapter.change_password(new_p, username=target_u)
            if pwd_ok:
                result["password_used"] = new_p
                pwd_changed_msg = f"Password {target_u} diubah"
                save_cached_credential(ip, target_u, new_p)
                if device.get("mac"):
                    save_cached_credential(device["mac"], target_u, new_p)
            else:
                pwd_changed_msg = f"Gagal ganti pwd ({pwd_msg})"
        except Exception as e:
            pwd_changed_msg = f"Err pwd ({str(e)})"

    if hasattr(adapter, "lock_anti_reset"):
        lock_ok, lock_msg = adapter.lock_anti_reset(lock_config)
    elif hasattr(adapter, "burn_config_to_rom"):
        burn_ok, burn_msg = adapter.burn_config_to_rom()
        btn_ok, btn_msg = getattr(adapter, "disable_reset_button", lambda: (True, "OK"))()
        lock_ok = burn_ok or btn_ok
        lock_msg = f"Burn: {burn_msg} | Button: {btn_msg}"
    else:
        lock_ok = False
        lock_msg = "Adapter tidak mendukung fitur Anti-Reset"

    result["anti_reset_locked"] = lock_ok
    if pwd_changed_msg:
        result["message"] = f"{pwd_changed_msg} & {lock_msg}"
    else:
        result["message"] = lock_msg
    return result

def run_batch_anti_reset(
    devices: List[Dict[str, Any]],
    lock_config: Dict[str, Any],
    custom_creds: List[Tuple[str, str]] = None,
    max_workers: int = 35,
    callback = None
) -> List[Dict[str, Any]]:
    """
    Apply Anti-Reset lock concurrently across all target ONTs.
    """
    results = []
    total = len(devices)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_ont_anti_reset, dev, lock_config, custom_creds): dev
            for dev in devices
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            results.append(res)
            if callback:
                callback(completed, total, res)

    return sorted(results, key=lambda r: ipaddress.IPv4Address(r["ip"]))

CHECKPOINT_FILE = ".scan_checkpoint.json"

def get_default_export_dir() -> str:
    """
    Detect optimal storage directory:
    - Android / Termux: /sdcard/Download (if accessible/writable)
    - Fallback: ./output/ directory
    """
    sdcard_download = "/sdcard/Download"
    if os.path.exists(sdcard_download) and os.access(sdcard_download, os.W_OK):
        return sdcard_download
    
    out_dir = os.path.join(os.getcwd(), "output")
    try:
        os.makedirs(out_dir, exist_ok=True)
        return out_dir
    except Exception:
        return os.getcwd()

def save_scan_checkpoint(subnet: str, scanned_devices: List[Dict[str, Any]], pending_hosts: List[str] = None):
    """
    Save current scan state to checkpoint file for recovery.
    """
    try:
        data = {
            "subnet": subnet,
            "timestamp": time.time(),
            "pending_hosts": pending_hosts or [],
            "devices": [
                {
                    "ip": d.get("ip"),
                    "mac": d.get("mac"),
                    "vendor": d.get("vendor"),
                    "model": d.get("model") or d.get("vendor"),
                    "driver_name": d.get("driver_name"),
                    "open_ports": d.get("open_ports", []),
                    "login_success": d.get("login_success", False),
                    "username_used": d.get("username_used"),
                    "password_used": d.get("password_used"),
                    "pppoe_display": d.get("pppoe_display"),
                    "pppoe_password_display": d.get("pppoe_password_display"),
                    "gpon_sn_display": d.get("gpon_sn_display"),
                    "vlan_display": d.get("vlan_display"),
                    "wan_ip_display": d.get("wan_ip_display"),
                }
                for d in scanned_devices
            ]
        }
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def load_scan_checkpoint() -> Optional[Dict[str, Any]]:
    """
    Load saved scan checkpoint if present.
    """
    if not os.path.exists(CHECKPOINT_FILE):
        return None
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def clear_scan_checkpoint():
    """
    Remove scan checkpoint file on completion.
    """
    if os.path.exists(CHECKPOINT_FILE):
        try:
            os.remove(CHECKPOINT_FILE)
        except Exception:
            pass

def export_inventory_reports(
    devices: List[Dict[str, Any]],
    json_filename: str = "inventory_result.json",
    csv_filename: str = "inventory_result.csv"
) -> Tuple[str, str]:
    """
    Auto-export inventory scan results to JSON and CSV in storage directory.
    """
    target_dir = get_default_export_dir()
    json_path = os.path.join(target_dir, json_filename)
    csv_path = os.path.join(target_dir, csv_filename)

    export_data = []
    for d in devices:
        export_data.append({
            "ip": d.get("ip"),
            "vendor": d.get("vendor") or "-",
            "model": d.get("model") or d.get("vendor") or "-",
            "gpon_sn_mac": d.get("gpon_sn_display") or d.get("mac") or "-",
            "driver_name": d.get("driver_name") or (d.get("adapter").__class__.__name__ if d.get("adapter") else "-"),
            "login_success": d.get("login_success", False),
            "username_used": d.get("username_used") or "-",
            "pppoe_user": d.get("pppoe_display") or "-",
            "pppoe_password": d.get("pppoe_password_display") or "-",
            "vlan": d.get("vlan_display") or "-",
            "wan_ip": d.get("wan_ip_display") or "-"
        })

    # 1. JSON Export
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    # 2. CSV Export
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP", "Vendor", "Model", "GPON SN / MAC", "Driver Dipakai",
            "Status Login", "User Login", "Username PPPoE", "Password PPPoE",
            "VLAN", "IP WAN"
        ])
        for row in export_data:
            writer.writerow([
                row["ip"],
                row["vendor"],
                row["model"],
                row["gpon_sn_mac"],
                row["driver_name"],
                "BERHASIL" if row["login_success"] else "GAGAL",
                row["username_used"],
                row["pppoe_user"],
                row["pppoe_password"],
                row["vlan"],
                row["wan_ip"]
            ])

    return json_path, csv_path
