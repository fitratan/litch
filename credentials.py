import json
import os
import re
from typing import List, Tuple, Optional

DEFAULT_CREDENTIALS = [
    # Top 10 Field Cheat Sheet (95% Tembus di Lapangan RT/RW Net)
    ("telecomadmin", "admintelecom"), # Huawei GPON
    ("admin", "Telkomdso123"),        # ZTE F609 V1-V3
    ("admin", "telkomdso123"),        # ZTE F609 V1-V3 (lowercase)
    ("admin", "@LN2021FmZTE"),        # ZTE F670L / F609 V4
    ("admin", "admin"),               # Universal Factory Default
    ("admin", ""),                    # Tenda / D-Link (Password Kosong)
    ("admin", "%0%Zfhadmin"),         # FiberHome GPON
    ("admin", "vsoladmin"),           # VSOL XPON/GPON
    ("admin", "stdONUiopt"),          # ONU Generic Tiongkok / Realtek
    ("admin", "zepon123"),            # ZTE V2/V3
    ("root", "admin"),                # Huawei / ZTE Root
    ("admin", "admin123"),            # Universal Superadmin
    ("admin", "Admin123"),
    ("admin", "admin1234"),
    ("admin", "12345678"),
    ("admin", "123456"),
    ("admin", "1234"),
    ("admin", "password"),
    ("user", "user"),
    ("user", "user123"),
    ("user", "user1234"),

    # 1. ZTE Presets (F609, F670, F670L, F660, F601, F477, F470, GM220-S)
    ("admin", "Telkomdso123"),
    ("admin", "telkomdso123"),
    ("admin", "Telkom123"),
    ("admin", "telkom123"),
    ("admin", "zepon123"),
    ("admin", "zep2kjzol"),
    ("admin", "Fh722"),
    ("admin", "@LN2021FmZTE"),
    ("admin", "@LN2020FmZTE"),
    ("admin", "@LN2019FmZTE"),
    ("admin", "@LN2018FmZTEzxhn"),
    ("admin", "adminFmZTE"),
    ("admin", "adminFm"),
    ("admin", "wepon123"),
    ("admin", "zte_admin"),
    ("admin", "useradmin"),
    ("admin", "supportadmin"),
    ("admin", "gponadmin"),
    ("admin", "zte521"),
    ("root", "Zte521"),
    ("admin", "zte"),
    ("user", "Telkom123"),
    ("user", "password"),
    
    # 2. Huawei Presets (HG8245A, HG8245H, HG8245H5, HG8245Q, EG8145, EG8141)
    ("telecomadmin", "admintelecom"),
    ("admintelecom", "telecomadmin"),
    ("telecomadmin", "nE7jA%5m"),
    ("telecomadmin", "hwadmin"),
    ("telecomadmin", "Zte521"),
    ("telecomadmin", "adminHW"),
    ("Epadmin", "adminEp"),
    ("support", "theworldinyourhand"),
    ("support", "support"),
    ("root", "adminHW"),
    ("root", "Huawei12#$"),
    ("root", "admin"),
    ("root", "admin123"),
    ("user", "Huawei12#$"),
    
    # 3. Fiberhome Presets (AN5506-04, AN5506-02, AN5506-01, HG680, HG6243C)
    ("admin", "%0%Zfhadmin"),
    ("admin", "%0|F?H@f!berhO3e"),
    ("admin", "fhadmin"),
    ("fiberhomesuperadmin", "sfuhgu"),
    ("admin", "stdONUiopt"),
    ("admin", "stdONU101"),
    ("admin", "stdonu101"),
    ("admin", "FiberHome"),
    ("admin", "fiberhome"),
    ("user", "1234"),
    
    # 4. Nokia / Alcatel-Lucent Presets (G-240W-A, G-2425G-A, I-240W-A)
    ("admin", "ALC#Fhbn7"),
    ("admin", "adminGpon"),

    # 5. MyRepublic Presets (ZTE, Huawei, Dasan Zhone)
    ("admin", "myrepublic"),
    ("admin", "Myrepublic"),
    ("admin", "myrepublic123"),
    ("admin", "dasan"),
    ("dasan", "dasan"),

    # 6. Biznet Presets (ZTE F670L, Huawei EG8145V5, Sercomm, Genexis)
    ("admin", "biznet"),
    ("admin", "Biznet123"),
    ("admin", "biznet123"),
    ("admin", "biznet@123"),
    ("superadmin", "biznetsuper"),

    # 7. First Media, MNC Play & Oxygen.id
    ("cusadmin", "highspeed"),
    ("admin", "cisco"),
    ("admin", "Cisco123"),
    ("admin", "motorola"),
    ("admin", "f@st"),
    ("admin", "mncplay"),
    ("admin", "MNCPlay123"),
    ("admin", "oxygen"),
    ("admin", "Oxygen123"),
    ("admin", "moratel"),
    ("admin", "moratelindo"),

    # 8. VSOL / V-Solution Presets (XPON / GPON ONU)
    ("admin", "vsoladmin"),
    ("admin", "Xpon@Olt9417#"),
    ("root", "root"),

    # 9. C-Data / HSGQ / HIOSO / BDCOM / Raisecom / DBC / Richerlink / Netlink
    ("admin", "cdata"),
    ("admin", "hsgq"),
    ("admin", "hsgqadmin"),
    ("admin", "hioso"),
    ("admin", "bdcom"),
    ("admin", "raisecom"),
    ("admin", "dbcnet"),
    ("admin", "richerlink"),
    ("admin", "netlink"),
    ("admin", "syrotech"),
    ("admin", "realtek"),

    # 10. Router SOHO / Wireless Outdoor (Ubiquiti, Tenda, TP-Link, Totolink, Mercusys, Netis)
    ("ubnt", "ubnt"),
    ("root", "ubnt"),
    ("admin", "tenda123"),
    ("tplink", "tplink"),
    ("admin", "totolink"),
    ("admin", "mercusys"),
    ("guest", "guest"),
]

DEFAULT_PASSWORDS_FILE = "passwords.txt"

def load_custom_passwords(file_path: str = DEFAULT_PASSWORDS_FILE) -> List[Tuple[str, str]]:
    custom_creds = []
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if ":" in line:
                            u, p = line.split(":", 1)
                            custom_creds.append((u.strip(), p.strip()))
                        elif " " in line:
                            u, p = line.split(" ", 1)
                            custom_creds.append((u.strip(), p.strip()))
                        else:
                            # Single password -> try as admin, empty username, and user
                            custom_creds.append(("admin", line))
                            custom_creds.append(("", line))
                            custom_creds.append(("user", line))
        except Exception:
            pass
    return custom_creds

def save_custom_passwords(creds: List[Tuple[str, str]], file_path: str = DEFAULT_PASSWORDS_FILE):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("# Daftar Password Kredensial ONT Modem NODERA\n")
            f.write("# Format: username:password atau password saja\n")
            for u, p in creds:
                f.write(f"{u}:{p}\n")
    except Exception as e:
        print(f"[Warning] Gagal menyimpan file password: {e}")

def get_credentials(custom_file: str = None) -> List[Tuple[str, str]]:
    """
    Get a deduplicated list of credentials (username, password).
    Loads custom credentials file if provided or default passwords.txt.
    """
    # 1. Start with custom user-defined passwords first (highest priority)
    file_to_load = custom_file or DEFAULT_PASSWORDS_FILE
    custom_creds = load_custom_passwords(file_to_load) if os.path.exists(file_to_load) else []
    
    # 2. Append default presets
    all_creds = custom_creds + list(DEFAULT_CREDENTIALS)

    # Deduplicate while preserving priority order
    seen = set()
    deduped = []
    for u, p in all_creds:
        if (u, p) not in seen:
            seen.add((u, p))
            deduped.append((u, p))

    return deduped

CACHE_CREDS_FILE = ".cache_creds.json"

def get_cached_credentials(identifier: str) -> Optional[Tuple[str, str]]:
    """
    Retrieve previously successful working credentials for this IP or MAC.
    """
    if not identifier:
        return None
    if os.path.exists(CACHE_CREDS_FILE):
        try:
            with open(CACHE_CREDS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                val = data.get(identifier)
                if val and isinstance(val, list) and len(val) == 2:
                    return (str(val[0]), str(val[1]))
        except Exception:
            pass
    return None

def save_cached_credential(identifier: str, username: str, password: str):
    """
    Save successful working credentials to .cache_creds.json for instant reuse.
    """
    if not identifier:
        return
    data = {}
    if os.path.exists(CACHE_CREDS_FILE):
        try:
            with open(CACHE_CREDS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    data[identifier] = [username, password]
    try:
        with open(CACHE_CREDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def get_vendor_prioritized_credentials(vendor_name: str = "", custom_file: str = None, ip_or_mac: str = "") -> List[Tuple[str, str]]:
    """
    Reorder credentials so top matching vendor presets are tested first.
    If working credentials were saved in cache, try them first!
    """
    all_creds = get_credentials(custom_file)
    v = (vendor_name or "").lower()
    
    top_picks = []
    
    # 0. Cached working credentials from previous successful sessions (0 ms hit)
    if ip_or_mac:
        cached = get_cached_credentials(ip_or_mac)
        if cached:
            top_picks.append(cached)
            
        # Dynamic MAC-derived patterns (e.g., adminabcd, ZTE_ABCD)
        clean_id = re.sub(r'[^a-zA-Z0-9]', '', ip_or_mac)
        if len(clean_id) == 12:
            last_4_l = clean_id[-4:].lower()
            last_4_u = clean_id[-4:].upper()
            top_picks.extend([
                ("admin", f"admin{last_4_l}"),
                ("admin", f"ZTE_{last_4_u}"),
                ("admin", f"ZTE_{last_4_l}"),
                ("admin", f"zte{last_4_l}"),
            ])

    if any(k in v for k in ["myrepublic", "dasan"]):
        top_picks.extend([
            ("admin", "myrepublic"),
            ("admin", "Myrepublic"),
            ("admin", "myrepublic123"),
            ("admin", "dasan"),
            ("dasan", "dasan"),
            ("root", "admin"),
        ])
    elif any(k in v for k in ["biznet"]):
        top_picks.extend([
            ("admin", "biznet"),
            ("admin", "Biznet123"),
            ("admin", "biznet123"),
            ("admin", "biznet@123"),
            ("superadmin", "biznetsuper"),
        ])
    elif any(k in v for k in ["firstmedia", "first media", "hitron", "sagemcom", "mnc", "oxygen", "moratel"]):
        top_picks.extend([
            ("cusadmin", "highspeed"),
            ("admin", "cisco"),
            ("admin", "Cisco123"),
            ("admin", "motorola"),
            ("admin", "f@st"),
            ("admin", "mncplay"),
            ("admin", "MNCPlay123"),
            ("admin", "oxygen"),
            ("admin", "Oxygen123"),
            ("admin", "moratel"),
            ("admin", "moratelindo"),
        ])
    elif any(k in v for k in ["ubnt", "ubiquiti", "airmax", "unifi"]):
        top_picks.extend([
            ("ubnt", "ubnt"),
            ("root", "ubnt"),
            ("admin", "admin"),
        ])
    elif any(k in v for k in ["zte", "zxic", "f609", "f660", "f670", "f677", "zx-f677", "f477", "f470", "f460", "f663", "gm220", "c0d0ff"]):
        top_picks.extend([
            ("admin", "dnsolution"),
            ("admin", "admin"),
            ("user", "user"),
            ("superadmin", "suportadmin"),
            ("telecomadmin", "admintelecom"),
            ("admin", "Telkomdso123"),
            ("admin", "telkomdso123"),
            ("user", "telkomdso123"),
            ("admin", "@LN2021FmZTE"),
            ("admin", "admin123"),
            ("admin", "Admin123"),
            ("admin", ""),
            ("admin", "Telkom123"),
            ("admin", "telkom123"),
            ("admin", "gm220"),
            ("admin", "gm220admin"),
            ("admin", "GM220admin"),
            ("admin", "12345678"),
            ("admin", "123456"),
            ("admin", "1234"),
            ("admin", "password"),
            ("admin", "Password"),
            ("admin", "zepon123"),
            ("admin", "zep2kjzol"),
            ("admin", "Fh722"),
            ("admin", "@LN2020FmZTE"),
            ("admin", "@LN2019FmZTE"),
            ("admin", "@LN2018FmZTEzxhn"),
            ("admin", "adminFmZTE"),
            ("admin", "adminFm"),
            ("admin", "wepon123"),
            ("admin", "zxic"),
            ("admin", "zxic1234"),
            ("admin", "ZXIC1234"),
            ("admin", "zxicadmin"),
            ("admin", "F677admin"),
            ("admin", "zte_admin"),
            ("admin", "useradmin"),
            ("admin", "supportadmin"),
            ("admin", "gponadmin"),
            ("admin", "zte521"),
            ("root", "Zte521"),
            ("admin", "zte"),
            ("user", "user"),
            ("user", "Telkom123"),
            ("superadmin", "supportadmin"),
            ("superadmin", "admin"),
            ("admin", "dnsolution123"),
            ("admin", "DNSolution"),
        ])
    elif any(k in v for k in ["huawei", "hg8245", "eg8145", "hg8546", "hg8010", "hg8310"]):
        top_picks.extend([
            ("telecomadmin", "admintelecom"),
            ("admintelecom", "telecomadmin"),
            ("telecomadmin", "nE7jA%5m"),
            ("telecomadmin", "hwadmin"),
            ("telecomadmin", "Zte521"),
            ("telecomadmin", "adminHW"),
            ("Epadmin", "adminEp"),
            ("support", "theworldinyourhand"),
            ("support", "support"),
            ("root", "adminHW"),
            ("root", "Huawei12#$"),
            ("root", "admin"),
            ("admin", "admin"),
            ("admin", "admin123"),
            ("user", "Huawei12#$"),
            ("user", "user"),
        ])
    elif any(k in v for k in ["fiberhome", "an5506", "hg680"]):
        top_picks.extend([
            ("admin", "%0%Zfhadmin"),
            ("admin", "%0|F?H@f!berhO3e"),
            ("admin", "fhadmin"),
            ("fiberhomesuperadmin", "sfuhgu"),
            ("admin", "stdONUiopt"),
            ("admin", "stdONU101"),
            ("admin", "FiberHome"),
            ("admin", "fiberhome"),
            ("admin", "admin"),
            ("admin", "admin123"),
            ("user", "1234"),
            ("user", "user"),
        ])
    elif any(k in v for k in ["nokia", "alcatel", "g-240w", "g-2425"]):
        top_picks.extend([
            ("admin", "ALC#Fhbn7"),
            ("admin", "adminGpon"),
            ("admin", "admin"),
            ("admin", "admin123"),
            ("root", "admin"),
        ])
    elif any(k in v for k in ["vsol", "v-solution"]):
        top_picks.extend([
            ("admin", "vsoladmin"),
            ("admin", "Xpon@Olt9417#"),
            ("admin", "stdONUiopt"),
            ("admin", "stdONU101"),
            ("admin", "admin"),
            ("admin", "admin123"),
            ("root", "root"),
        ])
    elif any(k in v for k in ["c-data", "cdata", "hsgq", "hioso", "bdcom", "xpon", "epon", "v2801", "fd511", "raisecom", "dbc", "richerlink"]):
        top_picks.extend([
            ("admin", "cdata"),
            ("admin", "hsgq"),
            ("admin", "hsgqadmin"),
            ("admin", "hioso"),
            ("admin", "bdcom"),
            ("admin", "raisecom"),
            ("admin", "dbcnet"),
            ("admin", "richerlink"),
            ("admin", "netlink"),
            ("admin", "syrotech"),
            ("admin", "realtek"),
            ("admin", "admin"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "admin"),
        ])
    elif any(k in v for k in ["tenda"]):
        top_picks.extend([
            ("admin", ""),
            ("admin", "admin"),
            ("admin", "tenda123"),
            ("admin", "admin123"),
            ("admin", "12345678"),
        ])
    elif any(k in v for k in ["tp-link", "tplink"]):
        top_picks.extend([
            ("admin", "admin"),
            ("tplink", "tplink"),
            ("admin", "admin123"),
            ("admin", ""),
            ("admin", "12345678"),
        ])

    file_to_load = custom_file or DEFAULT_PASSWORDS_FILE
    custom_creds = load_custom_passwords(file_to_load) if os.path.exists(file_to_load) else []
    
    ordered = []
    seen = set()

    # 0. Cached credentials for this IP/MAC (0ms)
    if ip_or_mac:
        cached = get_cached_credentials(ip_or_mac)
        if cached and cached not in seen:
            seen.add(cached)
            ordered.append(cached)

    # 1. Vendor top picks (ZTE, Huawei, FiberHome, etc.)
    for item in top_picks:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    # 2. Custom User-Defined Passwords from passwords.txt
    for item in custom_creds:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    # 3. Remaining presets
    for item in all_creds:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
            
    return ordered
