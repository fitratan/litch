# Litch — Multi-Vendor ONT Provisioning, Security Audit & Fleet Management Engine

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux%20%7C%20macOS-green.svg)](https://github.com/fitratan/litch)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](https://github.com/fitratan/litch)

**Litch** is a high-performance, asynchronous terminal management suite (Python CLI) designed for ISPs, WISPs, and network administrators. It automates fleet-wide discovery, penetration testing, vulnerability auditing, rogue DHCP detection, batch WAN/Wi-Fi provisioning, and permanent anti-reset hardening across GPON, EPON, XPON ONTs, and SOHO LAN routers.

---

## 🚀 Key Features

### 1. 🛡️ Penetration Testing & Vulnerability Auditing
- **Default Factory Credential Auditing**: Automated detection of default ISP & factory accounts (SuperAdmin, Admin, User).
- **Cleartext Root Telnet Backdoor Detection**: Flags active root shells (`root:Zte521`, `root:adminHW`, `root:admin`, etc.).
- **Open Recursive DNS Resolver Test**: Identifies devices vulnerable to participating in DNS amplification DDoS attacks.
- **SNMP Public Community Probe**: Scans for information disclosure via default SNMP `public` strings.
- **High-Risk Port Audit**: Inspects ports `21` (FTP), `22` (SSH), `23` (Telnet), `53` (DNS), `80/443/8080` (Web), `161` (SNMP), and `7547` (TR-069 CWMP).
- **Automated Risk Scoring**: Categorizes each host into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `SECURE`.
- **Comprehensive Reports**: Exports audit results into timestamped CSV and JSON files.

### 2. 🚨 Rogue DHCP Server Detection
- Broadcasts Layer-2 `DHCP Discover` packets (`255.255.255.255:67`) to locate unauthorized DHCP servers that cause IP conflicts and disconnect client networks.

### 3. ⚡ High-Speed Network Discovery
- Ultra-fast multi-threaded socket probe (up to 100+ concurrent workers) capable of scanning `/24` subnets in seconds.
- Multi-protocol fallback (Web HTTP/HTTPS, Telnet CLI, TR-069) with automatic MAC OUI vendor resolution.

### 4. ⚙️ Batch WAN Provisioning & OMCI Lock Bypass
- Switch WAN modes across hundreds of ONTs simultaneously (**PPPoE**, **IPoE/DHCP**, **Bridge**).
- Mass **VLAN ID** configuration.
- Dynamic PPPoE username & password injection with `{ip_last}` pattern support (e.g., `user_{ip_last}`).
- **TR-069 ACS URL** auto-configuration (e.g., GenieACS).
- **Multi-Layer OMCI / OAM Lock Bypass**: Overrides read-only kernel flags (`IsOMCICreated=0`, writeable attribute injection, and direct NVRAM DB write) on OLT-locked ZTE ONTs.

### 5. 📶 Dual-Band & Multi-SSID Wi-Fi Management
- Configure primary and secondary SSIDs, security protocols (WPA/WPA2-PSK), and passwords.
- Dual-band support for 2.4 GHz and 5 GHz networks (e.g., ZTE ZXHN F672Y).

### 6. 🔒 Permanent Anti-Reset Hardening
- **ROM Default Burn**: Commits active configurations to permanent Flash NVRAM so factory resets restore ISP settings.
- **Hardware Button Deactivation**: Remotely disables physical push-button reset listeners on supported OpenWrt, Tenda, and TP-Link devices.

### 7. 🔐 Master Authentication Guard
- Protected by **PBKDF2-HMAC-SHA256 (200,000 iterations)** cryptographic hashing.
- Digital **HMAC anti-tamper signature** preventing unauthorized file modifications.
- Rate-limited login barrier (maximum 3 attempts) before CLI tools can be opened.

---

## 📡 Supported Vendors & Hardware

| Vendor | Models / Series | Supported Protocols |
| :--- | :--- | :--- |
| **ZTE** | GM220-S, F663NV9, F477, F672Y, F670L, F609, F660 | Web GUI (Lua SPA / GCH), Telnet CLI |
| **Huawei** | HG8245A, HG8245H, HG8245Q, EG8145V5, HS8545M | Web ASP / WebFig, Telnet CLI |
| **Fiberhome** | AN5506-04, HG6245D, HG6243C | Web GUI, Telnet CLI |
| **VSOL / Realtek** | V2801SG, V2802RH, Realtek Boa OEM XPON | Boa Web API, Form Post |
| **Tenda** | N301, F3, F6, F9, AC6, AC10, AC23, HG9 | GoAhead Web API, Telnet Root |
| **TP-Link** | TL-WR840N, TL-WR844N, Archer C20/C50/C24, OpenWrt / LuCI | UserRpm Web, LuCI API, Agile Config |
| **MikroTik** | RouterOS v6 / v7 (Gateway / PPPoE Server Inspection) | REST API, Winbox / WebFig Probe |

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Linux, Termux (Android), or macOS

### Setup
```bash
# 1. Clone repository
git clone https://github.com/fitratan/litch.git
cd litch

# 2. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### 1. Interactive Wizard Mode (Recommended)
Launch the interactive terminal interface:
```bash
python3 main.py
```
Upon startup, authenticate with your master credentials. The interactive menu provides access to all 12 management operations:
```text
====================================================================
           LITCH — MULTI-VENDOR ONT MANAGEMENT ENGINE
====================================================================
   [1] Penetration Testing & Vulnerability Audit
   [2] Detect Rogue DHCP Servers on LAN
   [3] Batch WAN Configuration (PPPoE / VLAN / TR-069)
   [4] Batch Multi-SSID / Wi-Fi Configuration
   [5] Batch LAN Port Control (Enable / Disable Ports)
   [6] Batch Admin / ONT Credential Password Change
   [7] Audit / Test ONT Credentials Only
   [8] Scan & Deep Device Inventory (Export PPPoE / SN / RX Power)
   [9] Batch Reboot ONT
   [10] Credential Dictionary Management
   [11] Batch Anti-Reset Hardening (ROM Burn & Button Lock)
   [12] Change Master Application Credentials
   [0] Exit
```

### 2. One-Liner CLI Automation

#### Network Discovery & Deep Inventory Export:
```bash
python3 main.py --inventory --subnet 192.168.1.0/24 --threads 50
```

#### Batch WAN Provisioning:
```bash
python3 main.py --scan 192.168.1.0/24 --mode PPPoE --vlan 223 --pppoe-user user_{ip_last} --pppoe-pass secret123 --tr069 http://acs.yourdomain.com:7547
```

#### Run Penetration Testing & Vulnerability Audit:
```bash
python3 main.py --pentest --subnet 192.168.1.0/24
```

#### Run Batch Anti-Reset Hardening:
```bash
python3 main.py --anti-reset --subnet 192.168.1.0/24
```

#### Rogue DHCP Server Detection:
```bash
python3 main.py --rogue-dhcp
```

---

## 🔒 Security & Privacy Notice
- All network interactions, credential verifications, and audit actions execute entirely locally within your network.
- No telemetry, analytics, or external credentials are ever sent over third-party connections.
- Sensitive files (`.auth_security.json`, `.cache_creds.json`, CSV reports) are automatically excluded via `.gitignore`.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
