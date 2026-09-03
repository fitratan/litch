# ONT Network Discovery, Batch Provisioner & Penetration Testing Suite (CLI)

Aplikasi terminal mandiri (Python CLI) untuk scanning massal perangkat ONT modem dalam satu jaringan LAN / Subnet, melakukan penetration testing & audit kerentanan keamanan, deteksi rogue DHCP, serta otomatisasi konfigurasi WAN / Multi-SSID / Kredensial secara massal.

## Fitur Utama
1. **Penetration Testing & Vulnerability Audit**:
   - Audit kredensial default bawaan pabrik (SuperAdmin, Admin, User).
   - Deteksi akses root backdoor Telnet tanpa enkripsi (`root:Zte521`, `root:adminHW`, `root:admin`, dll).
   - Deteksi Open Recursive DNS Resolver (uji reflektor serangan DDoS Amplification).
   - Deteksi SNMP terbuka dengan default community `public`.
   - Pemindaian port berisiko tinggi (Telnet 23, FTP 21, SSH 22, Web 80/8080/443, TR-069 7547, DNS 53, SNMP 161).
   - Penilaian Tingkat Risiko & Skor Keamanan per perangkat (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SECURE`).
   - Ekspor laporan audit keamanan ke file `laporan_pentest_ont.csv` atau `laporan_pentest_ont.json`.
2. **Deteksi Rogue DHCP Server**:
   - Mengirim broadcast DHCP Discover untuk mendeteksi DHCP server liar di segmen LAN yang berpotensi memutus koneksi internet pelanggan.
3. **Fast Subnet Discovery**: Multi-threaded scanner untuk mendeteksi seluruh IP aktif, port web management (80/8080/443), dan port TR-069 (7547).
4. **Vendor Fingerprinting**: Otomatis mendeteksi model dan vendor ONT (**ZTE, Huawei, Fiberhome, XPON/VSOL, Tenda, TP-Link, MikroTik**).
5. **Multi-Credential Technician Profiles**: Mendukung kamus kredensial teknisi default ISP + custom list password.
6. **Batch WAN Provisioning & Hardening**:
   - Ganti mode WAN ke **PPPoE**, **IPoE (DHCP)**, atau **Bridge**.
   - Set **VLAN ID** massal.
   - Set **PPPoE Username & Password** (mendukung variabel dinamis `{ip_last}`).
   - Set **TR-069 GenieACS ACS URL** otomatis.
   - Batch ganti password admin/user secara massal.
   - Batch kontrol port LAN dan konfigurasi Wi-Fi Multi-SSID.
7. **Interactive & One-Liner CLI**: Tampilan terminal interaktif yang rapi dengan tabel warna Rich, progress bar, dan ekspor laporan CSV/JSON.

---

## Cara Menjalankan

Masuk ke direktori:
```bash
cd /home/rimuru/Projects/ont-batch-manager
```

### 1. Mode Interaktif (Wizard Lengkap)
Cukup jalankan:
```bash
python3 main.py
```
Aplikasi akan menanyakan:
- Subnet CIDR (otomatis mendeteksi IP LAN Anda saat ini).
- Pilihan aksi (Ubah WAN, Cek Login saja, atau Ekspor IP).
- Parameter WAN (Mode, VLAN, Username/Password PPPoE, TR-069 ACS).
- Menampilkan rekapitulasi tabel dan menyimpan file laporan `laporan_ont_provisioning.csv`.

### 2. Mode Perintah Satu Baris (CLI Flags)
Untuk otomatisasi atau skrip batch:
```bash
python3 main.py --scan 192.168.1.0/24 --mode PPPoE --vlan 100 --pppoe-user user_{ip_last} --pppoe-pass 123456 --tr069 http://acs.domainisp.com:7547
```

### 3. Menggunakan Custom File Password Teknisi
Buat file teks `passwords.txt`:
```text
admin:telkomdso123
telecomadmin:admintelecom
admin:%0%Zfhadmin
admin:rahasia123
```
Lalu jalankan:
```bash
python3 main.py --custom-creds passwords.txt
```
