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
    custom_creds: List[Tuple[str, str]] = None
) -> Tuple[bool, Optional[str], Optional[str], Any]:
    """
    Ensure the ONT adapter is authenticated cleanly:
    - Uses existing authenticated session if active
    - Prioritizes custom creds + vendor-specific defaults
    - Automatically falls back to ZTEAdapter if GenericAdapter was initially assigned
    - Caches successful credentials for subsequent operations
    """
    ip = device["ip"]
    adapter = device.get("adapter")

    if adapter and getattr(adapter, "authenticated_user", None):
        return True, adapter.authenticated_user, adapter.authenticated_password, adapter

    # Build prioritized credential candidates
    v_creds = get_vendor_prioritized_credentials(device.get("vendor", ""), ip_or_mac=ip)
    if custom_creds:
        combined = []
        for c in custom_creds + v_creds:
            if c not in combined:
                combined.append(c)
        creds_list = combined[:25]
    else:
        creds_list = v_creds[:25]

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

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
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
            user = wan.get("pppoe_user")
            pwd = wan.get("pppoe_password")
            sn = wan.get("gpon_sn")
            dev_data["pppoe_user"] = user
            dev_data["pppoe_password"] = pwd
            dev_data["vlan"] = wan.get("vlan")
            dev_data["wan_ip"] = wan.get("wan_ip")
            dev_data["pppoe_display"] = user or "-"
            dev_data["pppoe_password_display"] = pwd or "-"
            dev_data["gpon_sn_display"] = sn or dev_data.get("mac") or "-"

            # Update exact Model and SN if parsed from ONT status pages
            if wan.get("model"):
                dev_data["vendor"] = wan["model"]
            if wan.get("gpon_sn"):
                dev_data["gpon_sn"] = wan["gpon_sn"]
                dev_data["gpon_sn_display"] = wan["gpon_sn"]

            if wan.get("vlan"):
                dev_data["vlan_display"] = str(wan.get("vlan"))
            if wan.get("wan_ip"):
                dev_data["wan_ip_display"] = str(wan.get("wan_ip"))
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

    ok, user_used, pass_used, adapter = ensure_authenticated_device(device, custom_creds)
    if not ok:
        return result

    result["login_success"] = True
    result["username_used"] = user_used
    result["password_used"] = pass_used

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
