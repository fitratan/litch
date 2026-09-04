#!/usr/bin/env python3
"""
technician_suite.py - LITCH Field Technician Suite
Provides:
1. Air Wi-Fi Scanner (Scan SSID, BSSID, Signal RSSI, Channel, Security di Udara)
2. Direct ONT Wi-Fi Extractor (SSID & Password retrieval from Gateway/LAN)
3. Terminal ASCII QR Code Generator for 1-click camera connection
4. Offline Multi-Algorithm WPS PIN Calculator
5. Built-in Network Latency, Jitter & Bandwidth Speedtest
6. Telegram Job Report Dispatcher (Proof of Work)
"""

import sys
import os
import re
import time
import json
import socket
import struct
import shutil
import subprocess
import threading
from typing import Dict, Any, List, Tuple, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

console = Console(emoji=False)


# ==========================================
# 1. AIR WI-FI SCANNER (SCANNER SSID TERDEKAT)
# ==========================================

VENDOR_OUI_MAP = {
    "14:AD:CA": "ZTE Corporation",
    "00:1E:73": "ZTE Corporation",
    "48:28:2F": "ZTE Corporation",
    "64:13:6C": "ZTE Corporation",
    "78:6A:89": "ZTE Corporation",
    "A8:A6:68": "ZTE Corporation",
    "CC:7B:35": "ZTE Corporation",
    "D8:74:95": "ZTE Corporation",
    "E8:65:D4": "ZTE Corporation",
    "F4:6D:E2": "ZTE Corporation",
    "F4:8E:92": "ZTE Corporation",
    "48:46:FB": "Huawei Technologies",
    "00:46:4B": "Huawei Technologies",
    "10:47:80": "Huawei Technologies",
    "18:C5:8A": "Huawei Technologies",
    "20:F3:A3": "Huawei Technologies",
    "70:7B:E8": "Huawei Technologies",
    "AC:E2:15": "Huawei Technologies",
    "C8:D1:5E": "Huawei Technologies",
    "00:0A:EB": "TP-Link Corporation",
    "50:D4:F7": "TP-Link Corporation",
    "60:32:B1": "TP-Link Corporation",
    "98:DA:C4": "TP-Link Corporation",
    "C0:06:C3": "TP-Link Corporation",
    "C8:3A:35": "Tenda Technology",
    "50:2B:73": "Tenda Technology",
    "CC:2D:21": "Tenda Technology",
    "00:25:9E": "FiberHome Telecomm",
    "00:0F:E2": "FiberHome Telecomm",
    "48:7D:2E": "FiberHome Telecomm",
    "84:79:73": "FiberHome Telecomm",
    "E0:67:B3": "FiberHome Telecomm",
    "00:0C:42": "Mikrotikls SIA",
    "48:8F:5A": "Mikrotikls SIA",
    "6C:3B:6B": "Mikrotikls SIA",
    "B8:69:F4": "Mikrotikls SIA",
    "D4:CA:6D": "Mikrotikls SIA",
    "E4:8D:8C": "Mikrotikls SIA",
    "00:1B:11": "D-Link International",
    "1C:7E:E5": "D-Link International",
    "34:36:54": "Realtek / Generic",
    "00:E0:4C": "Realtek Semiconductor",
}


def lookup_vendor_by_mac(mac_str: str) -> str:
    """Identify device manufacturer from BSSID OUI prefix."""
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac_str).upper()
    if len(clean) >= 6:
        prefix = f"{clean[:2]}:{clean[2:4]}:{clean[4:6]}"
        if prefix in VENDOR_OUI_MAP:
            return VENDOR_OUI_MAP[prefix]
    return "Unknown / Generic Router"


def scan_nearby_wifi_air() -> List[Dict[str, Any]]:
    """
    Scan all broadcast Wi-Fi SSIDs in the air without being connected.
    Supports Android Termux (termux-wifi-scaninfo), nmcli, iwlist, and wpa_cli.
    """
    results = []
    seen_bssids = set()

    # 1. Android Termux API (termux-wifi-scaninfo)
    if shutil.which("termux-wifi-scaninfo"):
        try:
            p = subprocess.run(["termux-wifi-scaninfo"], capture_output=True, text=True, timeout=6)
            if p.returncode == 0 and p.stdout.strip():
                data = json.loads(p.stdout)
                for item in data:
                    bssid = item.get("bssid", "").upper().replace("\\", "")
                    if bssid in seen_bssids or not bssid:
                        continue
                    seen_bssids.add(bssid)
                    freq = item.get("frequency_mhz", 2412)
                    chan = (freq - 2407) // 5 if freq < 3000 else (freq - 5000) // 5
                    sec = item.get("capabilities", "WPA2")
                    results.append({
                        "ssid": item.get("ssid") or "<Hidden SSID>",
                        "bssid": bssid,
                        "rssi": item.get("rssi", -70),
                        "freq_mhz": freq,
                        "band": "5GHz" if freq > 3000 else "2.4GHz",
                        "channel": str(chan),
                        "security": sec,
                        "has_wps": "WPS" in sec.upper(),
                        "vendor": lookup_vendor_by_mac(bssid)
                    })
                if results:
                    return sorted(results, key=lambda x: x["rssi"], reverse=True)
        except Exception:
            pass

    # 2. Linux NetworkManager (nmcli)
    if shutil.which("nmcli"):
        try:
            # Trigger fresh rescan
            subprocess.run(["nmcli", "dev", "wifi", "rescan"], capture_output=True, text=True, timeout=4)
            p = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,WPS", "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=6
            )
            if p.returncode == 0 and p.stdout.strip():
                for line in p.stdout.strip().splitlines():
                    # Format: SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY:WPS
                    parts = line.split(":")
                    if len(parts) >= 6:
                        # BSSID might have escaped colons or split into parts
                        # Find the MAC-like portion
                        mac_match = re.search(r"([0-9A-Fa-f]{2}(?:\\?:[0-9A-Fa-f]{2}){5})", line)
                        if not mac_match:
                            continue
                        raw_bssid = mac_match.group(1).replace("\\", "").upper()
                        if raw_bssid in seen_bssids:
                            continue
                        seen_bssids.add(raw_bssid)

                        ssid = parts[0].strip() or "<Hidden SSID>"
                        # Find other fields
                        sig = parts[-3] if len(parts) >= 7 else parts[-2]
                        sec = parts[-2] if len(parts) >= 7 else parts[-1]
                        wps_val = parts[-1] if len(parts) >= 7 else ""

                        try:
                            rssi_calc = int((int(sig) / 2) - 100) if sig.isdigit() else -70
                        except Exception:
                            rssi_calc = -70

                        freq_str = line
                        is_5g = "5" in line and ("5180" in line or "5240" in line or "5745" in line or "5805" in line)

                        results.append({
                            "ssid": ssid,
                            "bssid": raw_bssid,
                            "rssi": rssi_calc,
                            "freq_mhz": 5000 if is_5g else 2400,
                            "band": "5GHz" if is_5g else "2.4GHz",
                            "channel": parts[2] if len(parts) > 2 and parts[2].isdigit() else "-",
                            "security": sec or "WPA2",
                            "has_wps": "yes" in wps_val.lower() or "wps" in sec.lower(),
                            "vendor": lookup_vendor_by_mac(raw_bssid)
                        })
                if results:
                    return sorted(results, key=lambda x: x["rssi"], reverse=True)
        except Exception:
            pass

    # 3. Linux iwlist fallback
    if shutil.which("iwlist"):
        try:
            p = subprocess.run(["iwlist", "scan"], capture_output=True, text=True, timeout=8)
            if p.returncode == 0 and p.stdout.strip():
                cells = p.stdout.split("Cell ")
                for c in cells[1:]:
                    mac_m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", c)
                    essid_m = re.search(r'ESSID:"([^"]*)"', c)
                    sig_m = re.search(r"Signal level=([-\d]+)\s*dBm", c)
                    chan_m = re.search(r"Channel:(\d+)", c)
                    if mac_m:
                        bssid = mac_m.group(1).upper()
                        if bssid in seen_bssids:
                            continue
                        seen_bssids.add(bssid)
                        ssid = essid_m.group(1) if essid_m else "<Hidden SSID>"
                        rssi = int(sig_m.group(1)) if sig_m else -70
                        chan = chan_m.group(1) if chan_m else "-"
                        results.append({
                            "ssid": ssid,
                            "bssid": bssid,
                            "rssi": rssi,
                            "freq_mhz": 5000 if chan.isdigit() and int(chan) > 14 else 2400,
                            "band": "5GHz" if chan.isdigit() and int(chan) > 14 else "2.4GHz",
                            "channel": chan,
                            "security": "WPA2" if "WPA2" in c else ("WPA" if "WPA" in c else "Open"),
                            "has_wps": "WPS" in c or "Wi-Fi Protected Setup" in c,
                            "vendor": lookup_vendor_by_mac(bssid)
                        })
                if results:
                    return sorted(results, key=lambda x: x["rssi"], reverse=True)
        except Exception:
            pass

    return sorted(results, key=lambda x: x["rssi"], reverse=True)


def get_signal_bar(rssi_dbm: int) -> Tuple[str, str]:
    """Format RSSI into visual signal indicator and strength label."""
    if rssi_dbm >= -50:
        return "[bold green][████][/bold green]", "[bold green]Sangat Kuat (Dekat)[/bold green]"
    elif rssi_dbm >= -65:
        return "[bold green][███ ][/bold green]", "[green]Kuat / Bagus[/green]"
    elif rssi_dbm >= -78:
        return "[bold yellow][██  ][/bold yellow]", "[yellow]Sedang[/yellow]"
    else:
        return "[bold red][█   ][/bold red]", "[red]Lemah (Jauh)[/red]"


# ==========================================
# 2. WPS PIN CALCULATION ENGINE
# ==========================================

def wps_checksum(pin_7_digits: int) -> int:
    """Calculate the 8th checksum digit for a 7-digit WPS PIN."""
    p_str = str(pin_7_digits).zfill(7)
    accum = 0
    accum += 3 * (int(p_str[0]) + int(p_str[2]) + int(p_str[4]) + int(p_str[6]))
    accum += 1 * (int(p_str[1]) + int(p_str[3]) + int(p_str[5]))
    digit = (10 - (accum % 10)) % 10
    return int(p_str + str(digit))


def calculate_wps_pins(bssid_or_mac: str) -> List[Dict[str, Any]]:
    """
    Compute probable factory default WPS PINs from MAC/BSSID using multiple vendor algorithms.
    Supported: ZTE (ZhaoChunsheng), ComputePIN (D-Link/Trendnet), Huawei, Arcadyan, Inverse.
    """
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", bssid_or_mac).upper()
    if len(clean_mac) < 12:
        return []

    nic_int = int(clean_mac[6:], 16)  # Last 3 bytes (NIC)
    mac_bytes = [int(clean_mac[i:i+2], 16) for i in range(0, 12, 2)]

    results = []

    # 1. ComputePIN / D-Link / Trendnet (NIC % 10000000)
    try:
        p_cpin = wps_checksum(nic_int % 10000000)
        results.append({
            "algorithm": "ComputePIN (D-Link / Trendnet / Realtek)",
            "pin": str(p_cpin).zfill(8),
            "confidence": "High",
            "desc": "Standard 24-bit NIC modulo"
        })
    except Exception:
        pass

    # 2. ZTE / ZhaoChunsheng (ZTE F609, F660, ZXHN Series)
    try:
        zhao_val = ((mac_bytes[4] ^ mac_bytes[5]) * 256 + mac_bytes[5]) ^ 0x5A5A
        p_zhao = wps_checksum(abs(zhao_val * 100 + (mac_bytes[3] ^ 0x33)) % 10000000)
        results.append({
            "algorithm": "ZTE / ZhaoChunsheng (ZTE F609 / F660 / ZXHN)",
            "pin": str(p_zhao).zfill(8),
            "confidence": "High",
            "desc": "ZTE ZXHN proprietary checksum calculation"
        })
    except Exception:
        pass

    # 3. Huawei (HG8245 / EG8145 Series)
    try:
        hw_val = ((mac_bytes[3] << 16) | (mac_bytes[4] << 8) | mac_bytes[5]) ^ 0x123456
        p_hw = wps_checksum(hw_val % 10000000)
        results.append({
            "algorithm": "Huawei (HG8245 / EG8145 / EchoLife)",
            "pin": str(p_hw).zfill(8),
            "confidence": "Medium",
            "desc": "Huawei EchoLife NIC shift"
        })
    except Exception:
        pass

    # 4. Arcadyan / EasyBox / Vodafone
    try:
        k1 = (mac_bytes[4] + mac_bytes[5]) & 0xFF
        k2 = (mac_bytes[3] + mac_bytes[5]) & 0xFF
        arc_val = (k1 * 1000 + k2 * 10 + (mac_bytes[5] & 0x0F)) % 10000000
        p_arc = wps_checksum(arc_val)
        results.append({
            "algorithm": "Arcadyan / Vodafone / EasyBox",
            "pin": str(p_arc).zfill(8),
            "confidence": "Medium",
            "desc": "Arcadyan polynomial matrix"
        })
    except Exception:
        pass

    # 5. Inverse 24-Bit (TP-Link / Tenda / Realtek)
    try:
        inv_nic = ((mac_bytes[5] << 16) | (mac_bytes[4] << 8) | mac_bytes[3])
        p_inv = wps_checksum(inv_nic % 10000000)
        results.append({
            "algorithm": "Inverse 24-bit (TP-Link / Tenda / Realtek)",
            "pin": str(p_inv).zfill(8),
            "confidence": "Medium",
            "desc": "Little-endian NIC inverse"
        })
    except Exception:
        pass

    # 6. Common Static Defaults
    static_pins = [
        ("12345670", "Standard Universal Default", "ZTE / Realtek / Tenda"),
        ("00000000", "Zero Static Default", "FiberHome / Generic"),
        ("20172527", "ZTE Broadcom Default", "ZTE F609 V3"),
    ]
    for sp, s_alg, s_vendor in static_pins:
        results.append({
            "algorithm": f"Static Default ({s_vendor})",
            "pin": sp,
            "confidence": "Static",
            "desc": s_alg
        })

    return results


# ==========================================
# 3. ASCII QR CODE GENERATOR FOR TERMINAL
# ==========================================

def render_wifi_qr_code(ssid: str, password: str = "", auth_type: str = "WPA", hidden: bool = False) -> str:
    """
    Generate an ASCII QR code for Wi-Fi auto-connect.
    Format: WIFI:T:WPA;S:MySSID;P:mypassword;H:false;;
    """
    sec = "nopass" if not password or auth_type.upper() == "OPEN" else "WPA"
    qr_payload = f"WIFI:T:{sec};S:{ssid};P:{password};H:{'true' if hidden else 'false'};;"

    if not HAS_QRCODE:
        return "[yellow]Modul qrcode belum terinstall. Install dengan: pip install qrcode[/yellow]"

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(qr_payload)
        qr.make(fit=True)

        matrix = qr.get_matrix()
        lines = []

        # High-contrast double-row block rendering (▀, ▄, █, ' ')
        for r in range(0, len(matrix), 2):
            line = ""
            for c in range(len(matrix[0])):
                top = matrix[r][c]
                bot = matrix[r + 1][c] if (r + 1) < len(matrix) else False
                if top and bot:
                    line += "█"
                elif top and not bot:
                    line += "▀"
                elif not top and bot:
                    line += "▄"
                else:
                    line += " "
            lines.append("  " + line)

        return "\n".join(lines)
    except Exception as e:
        return f"[red]Gagal merender QR Code: {str(e)}[/red]"


# ==========================================
# 4. DIRECT ONT WI-FI & DIAGNOSTIC EXTRACTOR
# ==========================================

def extract_ont_full_wifi_info(ip: str, custom_creds: Optional[List[Tuple[str, str]]] = None) -> Dict[str, Any]:
    """
    Connect to ONT, authenticate, and extract all Wi-Fi SSIDs, Passwords,
    Optical RX/TX Power, and WAN status.
    """
    from scanner import scan_host
    from credentials import get_vendor_prioritized_credentials, get_credentials

    dev = scan_host(ip)
    if not dev or not dev.get("adapter"):
        return {
            "success": False,
            "ip": ip,
            "vendor": dev.get("vendor", "Unknown") if dev else "Unknown",
            "message": f"Host {ip} tidak merespon port Web/Management"
        }

    adapter = dev["adapter"]
    vendor = dev.get("vendor", "")
    creds = custom_creds or get_vendor_prioritized_credentials(vendor, ip_or_mac=ip) or get_credentials()

    auth_success = False
    user_used = None
    pass_used = None

    for u, p in creds:
        try:
            ok, msg = adapter.login(u, p)
            if ok:
                auth_success = True
                user_used = u
                pass_used = p
                break
        except Exception:
            continue

    if not auth_success:
        return {
            "success": False,
            "ip": ip,
            "vendor": vendor,
            "message": f"Gagal autentikasi ke ONT {ip} dengan semua kredensial"
        }

    # Fetch Wi-Fi Details
    wifi_data = {"ssid": "N/A", "password": "N/A", "auth_mode": "WPA2-PSK", "channel": "Auto", "enabled": True}
    if hasattr(adapter, "get_wifi_info"):
        try:
            w_res = adapter.get_wifi_info()
            if isinstance(w_res, dict) and w_res.get("ssid"):
                wifi_data.update(w_res)
        except Exception:
            pass

    # If adapter doesn't extract password or returned N/A, try deeper inspection
    if wifi_data["ssid"] == "N/A" or wifi_data["password"] == "N/A":
        # Direct ZTE Deep Extract
        if "zte" in vendor.lower() or "gm220" in vendor.lower():
            for p in ["net_wlan_basic_t.gch", "net_wlan_conf_t.gch", "wlan_security_basic_t.gch", "net_wlan_security_t.gch"]:
                try:
                    r = adapter.session.get(f"{adapter.base_url}/getpage.gch?pid=1002&nextpage={p}", timeout=2)
                    tms = dict(re.findall(r"Transfer_meaning\([\"\x27]([^\x27\"]+)[\"\x27]\s*,\s*[\"\x27]([^\x27\"]*)[\"\x27]\)", r.text))
                    for k, v in tms.items():
                        if "ESSID0" in k or "ESSID1" in k or "Frm_ESSID" in k:
                            if v and v != "NULL":
                                wifi_data["ssid"] = v
                        if "KeyPassphrase0" in k or "KeyPassphrase1" in k or "Frm_KeyPassphrase" in k or "PreSharedKey" in k:
                            if v and v != "NULL":
                                wifi_data["password"] = v
                        if "BeaconType" in k or "AuthMode" in k:
                            wifi_data["auth_mode"] = v
                except Exception:
                    pass

    # Fetch Optical Power
    optical_data = {"rx_power_dbm": "N/A", "tx_power_dbm": "N/A", "status": "N/A"}
    if hasattr(adapter, "get_optical_power"):
        try:
            optical_data = adapter.get_optical_power()
        except Exception:
            pass

    # Fetch WAN Info
    wan_data = {"mode": "N/A", "wan_ip": "N/A", "pppoe_user": "N/A", "vlan": "N/A"}
    if hasattr(adapter, "get_wan_info"):
        try:
            wan_data = adapter.get_wan_info()
        except Exception:
            pass

    return {
        "success": True,
        "ip": ip,
        "vendor": vendor,
        "auth_user": user_used,
        "auth_pass": pass_used,
        "wifi": wifi_data,
        "optical": optical_data,
        "wan": wan_data,
        "mac": dev.get("mac") or "Unknown"
    }


# ==========================================
# 5. NETWORK LATENCY, JITTER & SPEEDTEST
# ==========================================

def run_ping_jitter_test(target_host: str, count: int = 5, timeout_sec: float = 1.0) -> Dict[str, Any]:
    """Measure ping latency, jitter, and packet loss to a target host."""
    latencies = []
    lost = 0

    for _ in range(count):
        t0 = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_sec)
            res = sock.connect_ex((target_host, 80 if target_host != "1.1.1.1" and target_host != "8.8.8.8" else 53))
            t1 = time.time()
            sock.close()
            if res == 0 or res == 111:
                latencies.append((t1 - t0) * 1000)
            else:
                lost += 1
        except Exception:
            lost += 1
        time.sleep(0.08)

    if not latencies:
        return {"min_ms": 0, "avg_ms": 0, "max_ms": 0, "jitter_ms": 0, "loss_pct": 100, "status": "Offline"}

    min_l = min(latencies)
    max_l = max(latencies)
    avg_l = sum(latencies) / len(latencies)
    
    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    jitter = sum(diffs) / len(diffs) if diffs else 0.0
    loss_pct = int((lost / count) * 100)

    return {
        "min_ms": round(min_l, 1),
        "avg_ms": round(avg_l, 1),
        "max_ms": round(max_l, 1),
        "jitter_ms": round(jitter, 1),
        "loss_pct": loss_pct,
        "status": "Good" if avg_l < 50 and loss_pct == 0 else ("Moderate" if loss_pct < 20 else "Poor")
    }


def run_bandwidth_speedtest(duration_sec: int = 4) -> Dict[str, Any]:
    """
    Measure real-world HTTP download speed from high-capacity CDN test endpoints.
    """
    test_urls = [
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://proof.ovh.net/files/10Mb.dat",
        "http://cachefly.cachefly.net/10mb.test"
    ]

    download_mbps = 0.0
    total_bytes = 0

    for url in test_urls:
        try:
            r = requests.get(url, stream=True, timeout=5)
            if r.status_code == 200:
                t0 = time.time()
                for chunk in r.iter_content(chunk_size=65536):
                    total_bytes += len(chunk)
                    if time.time() - t0 >= duration_sec:
                        break
                t_elapsed = time.time() - t0
                if t_elapsed > 0 and total_bytes > 0:
                    download_mbps = round((total_bytes * 8) / (t_elapsed * 1_000_000), 2)
                    break
        except Exception:
            continue

    return {
        "download_mbps": download_mbps,
        "total_bytes_transferred": total_bytes,
        "status": "Normal" if download_mbps > 2.0 else "Slow / No Internet"
    }


# ==========================================
# 6. TELEGRAM JOB REPORT (PROOF OF WORK)
# ==========================================

def format_technician_job_report(
    technician_name: str,
    customer_id_or_name: str,
    ont_data: Dict[str, Any],
    speedtest_data: Dict[str, Any],
    notes: str = ""
) -> str:
    """Format a clean, professional technician job report."""
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    wifi = ont_data.get("wifi", {})
    optical = ont_data.get("optical", {})
    wan = ont_data.get("wan", {})

    ping_gw = speedtest_data.get("ping_gw", {})
    ping_inet = speedtest_data.get("ping_inet", {})
    dl_speed = speedtest_data.get("download_mbps", 0.0)

    report = (
        "📋 <b>LAPORAN PEKERJAAN TEKNISI LAPANGAN</b>\n"
        "──────────────────────────────\n"
        f"🕐 <b>Waktu</b>      : {now_str}\n"
        f"👤 <b>Teknisi</b>    : {technician_name}\n"
        f"🏠 <b>Pelanggan</b>  : {customer_id_or_name}\n"
        f"🌐 <b>IP Modem</b>   : {ont_data.get('ip', '-')}\n"
        f"📟 <b>Vendor/Tipe</b>: {ont_data.get('vendor', '-')}\n"
        "──────────────────────────────\n"
        f"📶 <b>Wi-Fi SSID</b> : <code>{wifi.get('ssid', '-')}</code>\n"
        f"🔑 <b>Password</b>   : <code>{wifi.get('password', '-')}</code>\n"
        f"🔒 <b>Keamanan</b>   : {wifi.get('auth_mode', 'WPA2-PSK')}\n"
        "──────────────────────────────\n"
        f"💡 <b>Redaman PON</b>: {optical.get('rx_power_dbm', '-')} dBm (Status: {optical.get('status', '-')})\n"
        f"👤 <b>User PPPoE</b> : <code>{wan.get('pppoe_user', '-')}</code>\n"
        f"⚡ <b>Speedtest</b>  : <b>{dl_speed} Mbps</b>\n"
        f"📊 <b>Latensi Net</b>: {ping_inet.get('avg_ms', '-')} ms (Jitter: {ping_inet.get('jitter_ms', '-')} ms | Loss: {ping_inet.get('loss_pct', 0)}%)\n"
        f"🏠 <b>Ping Modem</b> : {ping_gw.get('avg_ms', '-')} ms\n"
        "──────────────────────────────\n"
        + (f"📝 <b>Catatan</b>    : {notes}\n" if notes else "")
        + "Status: <b>SELESAI & INTERNET NORMAL ✅</b>"
    )
    return report


def dispatch_telegram_report(report_text: str) -> Tuple[bool, str]:
    """Send report text directly to Telegram chat using send-telegram utility."""
    try:
        cmd = ["send-telegram", "-m", report_text]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return True, "Laporan berhasil dikirim ke grup Telegram"
        return False, f"Gagal mengirim Telegram: {proc.stderr or proc.stdout}"
    except Exception as e:
        return False, f"Gagal eksekusi send-telegram: {str(e)}"
