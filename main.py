#!/usr/bin/env python3
import sys
import os
import shutil
import argparse
import json
import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
from rich.markup import escape

from scanner import (
    get_active_subnets,
    get_default_gateway,
    get_default_local_subnet,
    get_arp_neighbors,
    get_all_detected_gateways_and_subnets,
    get_device_category,
    parse_target_network_input,
    check_port,
    discover_upstream_routing_hops,
    scan_host,
    scan_network
)
from batch_engine import (
    run_batch_provisioning,
    run_batch_password_change,
    run_batch_lan_config,
    run_batch_wlan_config,
    run_batch_reboot,
    run_batch_anti_reset,
    run_batch_device_inspection,
    export_inventory_reports,
    save_scan_checkpoint,
    load_scan_checkpoint,
    clear_scan_checkpoint,
    get_default_export_dir
)
from credentials import (
    get_credentials,
    get_vendor_prioritized_credentials,
    load_custom_passwords,
    save_custom_passwords,
    DEFAULT_PASSWORDS_FILE
)
from security_audit import run_batch_pentest, detect_rogue_dhcp_servers, AUDIT_PORTS
from auth import require_authentication, change_master_credentials

console = Console(emoji=False)

def get_term_width() -> int:
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return console.width or 80

def is_mobile_term() -> bool:
    return get_term_width() < 95

def print_banner():
    w = min(max(get_term_width() - 2, 35), 70)
    border = "+" + "=" * (w - 2) + "+"
    title = "LITCH - NETWORK BATCH & SECURITY"
    if len(title) > w - 4:
        title = "LITCH - BATCH & SEC"
    padding = max(0, (w - 2 - len(title)) // 2)
    line = "|" + " " * padding + title + " " * (w - 2 - len(title) - padding) + "|"
    console.print(f"[bold cyan]{border}\n{line}\n{border}[/bold cyan]")

def print_subnet_choices(detected_subnets):
    if is_mobile_term():
        console.print("[bold cyan]Daftar Subnet Terdeteksi:[/bold cyan]")
        for idx, s in enumerate(detected_subnets, 1):
            gw_str = f" | GW: {s.get('gateway')}" if s.get('gateway') else ""
            console.print(f"  [bold yellow][{idx}][/bold yellow] [bold green]{s['subnet']}[/bold green] ({s['source']}){gw_str} — [dim]{s['hosts']} Host[/dim]")
    else:
        sub_table = Table(title="Daftar Pool IP & Gateway Jaringan Terdeteksi", border_style="cyan")
        sub_table.add_column("No", justify="center", style="dim")
        sub_table.add_column("Sumber / Nama Pool IP", style="bold white")
        sub_table.add_column("Subnet CIDR", style="bold green")
        sub_table.add_column("Kelas Prefix", justify="center", style="yellow")
        sub_table.add_column("Gateway Target", style="cyan")
        sub_table.add_column("Estimasi Host", justify="right", style="white")
        sub_table.add_column("Status Pool", justify="center", style="green")

        for idx, s in enumerate(detected_subnets, 1):
            sub_table.add_row(
                str(idx),
                s["source"],
                s["subnet"],
                s["cidr"],
                s.get("gateway") or "-",
                f"{s['hosts']} Host",
                s.get("status") or "Tersedia"
            )
        console.print(sub_table)

def print_device_table(devices_list, is_deep: bool = False):
    if is_deep:
        login_success_count = sum(1 for d in devices_list if d.get("login_success"))
        console.print(f"\n[bold green]Total {len(devices_list)} perangkat diinventarisasi ({login_success_count} berhasil login):[/bold green]")
        
        if is_mobile_term():
            # Mobile / Termux Compact Card View (Max 60-70 columns)
            sep = "-" * min(get_term_width(), 65)
            for idx, dev in enumerate(devices_list, 1):
                driver_name = dev.get("driver_name") or (dev.get("adapter").__class__.__name__ if dev.get("adapter") else "-")
                cred_str = f"[bold green]{dev['username_used']}:{dev['password_used']}[/bold green]" if dev.get("login_success") else "[bold red]Gagal Login[/bold red]"
                pppoe_user = dev.get("pppoe_display") or "-"
                pppoe_pwd = dev.get("pppoe_password_display") or "-"
                sn_mac = dev.get("gpon_sn_display") or dev.get("mac") or "-"
                vlan_str = f" | VLAN: {dev.get('vlan_display')}" if dev.get("vlan_display") and dev.get("vlan_display") != "-" else ""

                console.print(f"[dim]{sep}[/dim]")
                console.print(f"[bold yellow][{idx}][/bold yellow] [bold white]{dev['ip']}[/bold white] — [bold cyan]{dev['vendor']}[/bold cyan]")
                console.print(f"    SN/MAC : [bold yellow]{sn_mac}[/bold yellow] ([dim]{driver_name}[/dim])")
                console.print(f"    Auth   : {cred_str}")
                console.print(f"    PPPoE  : [bold green]{pppoe_user}[/bold green] | Pass: [bold magenta]{pppoe_pwd}[/bold magenta]{vlan_str}")
            console.print(f"[dim]{sep}[/dim]")
        else:
            # Full Desktop Wide Table (Deep / Detailed)
            table = Table(title="Inventarisasi Multi-Vendor ONT & Router", border_style="cyan")
            table.add_column("No", justify="center", style="dim")
            table.add_column("IP Address", style="bold white")
            table.add_column("GPON SN / MAC", style="yellow")
            table.add_column("Vendor / Model", style="cyan")
            table.add_column("Driver", style="magenta")
            table.add_column("Status Login", style="yellow")
            table.add_column("Username PPPoE", style="bold green")
            table.add_column("Password PPPoE", style="bold magenta")
            table.add_column("VLAN", justify="center", style="cyan")

            for idx, dev in enumerate(devices_list, 1):
                cred_text = f"[bold green]{dev['username_used']}:{dev['password_used']}[/bold green]" if dev.get("login_success") else "[bold red]Gagal Login[/bold red]"
                driver_text = dev.get("driver_name") or (dev.get("adapter").__class__.__name__ if dev.get("adapter") else "-")
                pppoe_user = dev.get("pppoe_display") or "-"
                pppoe_pwd = dev.get("pppoe_password_display") or "-"
                vlan_text = dev.get("vlan_display") or "-"
                sn_mac = dev.get("gpon_sn_display") or dev.get("mac") or "-"
                
                table.add_row(
                    str(idx),
                    dev["ip"],
                    sn_mac,
                    dev["vendor"],
                    driver_text,
                    cred_text,
                    pppoe_user,
                    pppoe_pwd,
                    vlan_text
                )
            console.print(table)
    else:
        # Fast / Quick Scan Display (Directly for command execution)
        console.print(f"\n[bold green]Total {len(devices_list)} unit ONT/perangkat ditemukan di jaringan:[/bold green]")
        if is_mobile_term():
            sep = "-" * min(get_term_width(), 65)
            for idx, dev in enumerate(devices_list, 1):
                dev_type = dev.get("device_type") or get_device_category(dev.get("vendor", ""))
                ports_str = ",".join(map(str, dev.get("open_ports", [])))
                mac_str = f" | MAC: {dev.get('mac')}" if dev.get("mac") else ""
                console.print(f"[dim]{sep}[/dim]")
                console.print(f"[bold yellow][{idx}][/bold yellow] [bold white]{dev['ip']}[/bold white] — [bold cyan]{dev['vendor']}[/bold cyan] ([magenta]{dev_type}[/magenta])")
                console.print(f"    Ports: [cyan]{ports_str or '-'}[/cyan]{mac_str}")
            console.print(f"[dim]{sep}[/dim]")
        else:
            table = Table(title="Daftar Target ONT Terdeteksi (Siap Diberi Perintah)", border_style="cyan")
            table.add_column("No", justify="center", style="dim")
            table.add_column("IP Target", style="bold white")
            table.add_column("MAC Address", style="yellow")
            table.add_column("Vendor / Model", style="cyan")
            table.add_column("Tipe Perangkat", style="magenta")
            table.add_column("Port Terbuka", style="dim")

            for idx, dev in enumerate(devices_list, 1):
                ports_str = ",".join(map(str, dev.get("open_ports", [])))
                mac_text = dev.get("mac") or "-"
                dev_type = dev.get("device_type") or get_device_category(dev.get("vendor", ""))
                table.add_row(
                    str(idx),
                    dev["ip"],
                    mac_text,
                    dev["vendor"],
                    dev_type,
                    ports_str or "-"
                )
            console.print(table)

def print_pentest_results(pentest_results):
    console.print("\n[bold cyan]=== HASIL PENETRATION TESTING & AUDIT KERENTANAN ONT ===[/bold cyan]")
    
    crit_count = 0
    high_count = 0
    med_count = 0
    secure_count = 0

    for r in pentest_results:
        level = r["risk_level"]
        if level == "CRITICAL":
            crit_count += 1
        elif level == "HIGH":
            high_count += 1
        elif level == "MEDIUM":
            med_count += 1
        else:
            secure_count += 1

    if is_mobile_term():
        # Mobile / Termux Card View for Pentest
        sep = "-" * min(get_term_width(), 65)
        for idx, r in enumerate(pentest_results, 1):
            cred_text = f"[bold red]{r['active_user']}:{r['active_pass']}[/bold red]" if r["active_user"] else "[bold green]Terkunci/Non-Default[/bold green]"
            t_root = f"[bold red][VULN] ({r['telnet_backdoors'][0][0]}:{r['telnet_backdoors'][0][1]})[/bold red]" if r["telnet_backdoors"] else ("[yellow]Port 23 Buka[/yellow]" if 23 in r["open_ports"] else "[green]Tutup[/green]")
            
            dns_snmp = []
            if r["is_open_dns"]:
                dns_snmp.append("[red]Open DNS[/red]")
            if r["is_snmp_exposed"]:
                dns_snmp.append("[red]SNMP Public[/red]")
            dns_str = ", ".join(dns_snmp) if dns_snmp else "[green]Aman[/green]"
            
            ports_str = ",".join(str(p) for p in r["open_ports"][:6]) or "-"

            console.print(f"[dim]{sep}[/dim]")
            console.print(f"[bold yellow][{idx}][/bold yellow] [bold white]{r['ip']}[/bold white] ({r['vendor']}) -> [{r['risk_color']}][{r['risk_level']}][/ {r['risk_color']}] [dim]Skor: {r['risk_score']}/10[/dim]")
            console.print(f"    Login Web: {cred_text} | Telnet: {t_root}")
            console.print(f"    DNS/SNMP : {dns_str} | Ports: [cyan]{ports_str}[/cyan]")
            
            if r["vulnerabilities"]:
                for v in r["vulnerabilities"]:
                    v_color = "red" if v["severity"] in ["CRITICAL", "HIGH"] else "yellow"
                    console.print(f"    [*] [{v_color}][{v['severity']}][/{v_color}] {v['name']}")
        console.print(f"[dim]{sep}[/dim]")
    else:
        # Full Wide Desktop Table
        pt_table = Table(title="Laporan Audit Keamanan Jaringan ONT & Router", border_style="cyan")
        pt_table.add_column("No", justify="center", style="dim")
        pt_table.add_column("IP Target", style="bold white")
        pt_table.add_column("Vendor / Model", style="cyan")
        pt_table.add_column("Kredensial Default", style="yellow")
        pt_table.add_column("Telnet Root / Shell", justify="center")
        pt_table.add_column("Open DNS / SNMP", justify="center")
        pt_table.add_column("Port Terbuka", style="dim")
        pt_table.add_column("Skor Risiko", justify="center")
        pt_table.add_column("Level Risiko", justify="center")

        for idx, r in enumerate(pentest_results, 1):
            cred_text = f"[bold red]{r['active_user']}:{r['active_pass']}[/bold red]" if r["active_user"] else "[bold green]Terkunci / Non-Default[/bold green]"
            if r["telnet_backdoors"]:
                t_root_text = f"[bold red][VULN] ({r['telnet_backdoors'][0][0]}:{r['telnet_backdoors'][0][1]})[/bold red]"
            elif 23 in r["open_ports"]:
                t_root_text = "[yellow]Port 23 Terbuka[/yellow]"
            else:
                t_root_text = "[green]Tertutup[/green]"

            dns_snmp_items = []
            if r["is_open_dns"]:
                dns_snmp_items.append("[red]Open DNS[/red]")
            if r["is_snmp_exposed"]:
                dns_snmp_items.append("[red]SNMP Public[/red]")
            dns_snmp_text = ", ".join(dns_snmp_items) if dns_snmp_items else "[green]Aman[/green]"

            ports_str = ",".join(str(p) for p in r["open_ports"][:5])
            if len(r["open_ports"]) > 5:
                ports_str += "..."

            risk_badge = f"[{r['risk_color']}]{r['risk_level']}[/{r['risk_color']}]"
            score_badge = f"[{r['risk_color']}]{r['risk_score']}/10[/{r['risk_color']}]"

            pt_table.add_row(
                str(idx),
                r["ip"],
                r["vendor"],
                cred_text,
                t_root_text,
                dns_snmp_text,
                ports_str or "-",
                score_badge,
                risk_badge
            )
        console.print(pt_table)

        # Detailed findings breakdown on desktop
        vulnerable_targets = [r for r in pentest_results if r["vulnerabilities"]]
        if vulnerable_targets:
            console.print("\n[bold yellow]Rincian Kerentanan yang Terdeteksi pada Perangkat:[/bold yellow]")
            for vt in vulnerable_targets:
                console.print(f"\n   [bold white]Target IP: {vt['ip']}[/bold white] ({vt['vendor']}) — [{vt['risk_color']}]{vt['risk_level']}[/{vt['risk_color']}]:")
                for v in vt["vulnerabilities"]:
                    v_color = "red" if v["severity"] in ["CRITICAL", "HIGH"] else "yellow"
                    console.print(f"     [*] [{v_color}][{v['severity']}][/{v_color}] [bold]{v['name']}[/bold]")
                    console.print(f"         [dim]{v['desc']}[/dim]")

    # Summary Posture Panel
    summary_panel = Panel(
        f"[bold white]Total Perangkat Di-Audit :[/bold white] {len(pentest_results)} unit\n"
        f"[bold red]Kategori CRITICAL        :[/bold red] {crit_count} unit\n"
        f"[red]Kategori HIGH            :[/red] {high_count} unit\n"
        f"[yellow]Kategori MEDIUM          :[/yellow] {med_count} unit\n"
        f"[bold green]Kategori SECURE (Aman)   :[/bold green] {secure_count} unit",
        title="[bold cyan]Ringkasan Skor Postur Keamanan[/bold cyan]",
        border_style="cyan"
    )
    console.print(summary_panel)

def print_execution_summary(results, choice):
    console.print("\n[bold cyan]=== REKAPITULASI HASIL EKSEKUSI ===[/bold cyan]")
    
    success_login_count = 0
    success_action_count = 0

    for r in results:
        if r["login_success"]:
            success_login_count += 1
        if choice == "3" and r.get("wan_updated"):
            success_action_count += 1
        elif choice == "4" and r.get("wlan_updated"):
            success_action_count += 1
        elif choice == "5" and r.get("lan_updated"):
            success_action_count += 1
        elif choice == "6" and r.get("password_changed"):
            success_action_count += 1
        elif choice == "11" and r.get("anti_reset_locked"):
            success_action_count += 1

    if is_mobile_term():
        sep = "-" * min(get_term_width(), 65)
        for idx, r in enumerate(results, 1):
            login_badge = "[green][OK][/green]" if r["login_success"] else "[red][FAIL][/red]"
            cred_text = f"{r['username_used']}:{r['password_used']}" if r["username_used"] else "-"
            
            action_stat = ""
            if choice == "3":
                action_stat = " | WAN: [green]Updated[/green]" if r.get("wan_updated") else " | WAN: [red]Gagal[/red]"
            elif choice == "4":
                action_stat = " | Wi-Fi: [green]Updated[/green]" if r.get("wlan_updated") else " | Wi-Fi: [red]Gagal[/red]"
            elif choice == "5":
                action_stat = " | LAN: [green]Updated[/green]" if r.get("lan_updated") else " | LAN: [red]Gagal[/red]"
            elif choice == "6":
                action_stat = " | Pass: [green]Terganti[/green]" if r.get("password_changed") else " | Pass: [red]Gagal[/red]"
            elif choice == "11":
                action_stat = " | Anti-Reset: [green]Terkunci[/green]" if r.get("anti_reset_locked") else " | Anti-Reset: [red]Gagal[/red]"

            console.print(f"[dim]{sep}[/dim]")
            console.print(f"{login_badge} [bold white]{r['ip']}[/bold white] ({r['vendor']}){action_stat}")
            console.print(f"    Kredensial: {cred_text} — [dim]{r['message']}[/dim]")
        console.print(f"[dim]{sep}[/dim]")
    else:
        res_table = Table(border_style="cyan")
        res_table.add_column("IP Address", style="bold white")
        res_table.add_column("Vendor", style="cyan")
        res_table.add_column("Login Status", justify="center")
        res_table.add_column("Kredensial", style="yellow")
        if choice == "3":
            res_table.add_column("Status WAN", justify="center")
        elif choice == "4":
            res_table.add_column("Status Wi-Fi", justify="center")
        elif choice == "5":
            res_table.add_column("Status LAN", justify="center")
        elif choice == "6":
            res_table.add_column("Status Ganti Pass", justify="center")
        elif choice == "11":
            res_table.add_column("Status Anti-Reset", justify="center")
        res_table.add_column("Keterangan", style="dim")

        for r in results:
            login_badge = "[bold green]BERHASIL[/bold green]" if r["login_success"] else "[bold red]GAGAL[/bold red]"
            cred_text = f"{r['username_used']}:{r['password_used']}" if r["username_used"] else "-"

            if choice == "3":
                action_badge = "[bold green]TERUPDATE[/bold green]" if r.get("wan_updated") else "[bold red]GAGAL[/bold red]"
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, action_badge, r["message"])
            elif choice == "4":
                action_badge = "[bold green]TERKONFIGURASI[/bold green]" if r.get("wlan_updated") else "[bold red]GAGAL[/bold red]"
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, action_badge, r["message"])
            elif choice == "5":
                action_badge = "[bold green]TERKONFIGURASI[/bold green]" if r.get("lan_updated") else "[bold red]GAGAL[/bold red]"
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, action_badge, r["message"])
            elif choice == "6":
                action_badge = "[bold green]TERGANTI[/bold green]" if r.get("password_changed") else "[bold red]GAGAL[/bold red]"
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, action_badge, r["message"])
            elif choice == "11":
                action_badge = "[bold green]TERKUNCI (ROM)[/bold green]" if r.get("anti_reset_locked") else "[bold red]GAGAL[/bold red]"
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, action_badge, r["message"])
            else:
                res_table.add_row(r["ip"], r["vendor"], login_badge, cred_text, r["message"])

        console.print(res_table)

    summary_panel = Panel(
        f"[bold white]Total Target  :[/bold white] {len(results)} ONT\n"
        f"[bold green]Login Sukses  :[/bold green] {success_login_count} ONT\n"
        + (f"[bold cyan]Action Sukses :[/bold cyan] {success_action_count} ONT\n" if choice in ["3", "4", "5", "6", "11"] else "")
        + f"[bold red]Gagal Login   :[/bold red] {len(results) - success_login_count} ONT",
        title="[bold green]Ringkasan Eksekusi Selesai[/bold green]",
        border_style="green"
    )
    console.print(summary_panel)

def run_discovery_and_scan(creds, deep_inspect: bool = False):
    gw = get_default_gateway()
    gw_ip = gw['gateway_ip'] if gw else "192.168.1.1"
    
    console.print(f"\n[bold yellow]1. Memeriksa Gateway Lokal & Interface Jaringan...[/bold yellow]")
    if gw:
        console.print(f"   [bold green][OK] Gateway LAN PC Terdeteksi:[/bold green] [bold white]{gw['gateway_ip']}[/bold white] (Interface: [cyan]{gw['iface']}[/cyan])")
    
    gw_dev = scan_host(gw_ip)
    wan_info = {}
    
    if gw_dev:
        dev_type = gw_dev.get("device_type") or get_device_category(gw_dev.get("vendor", ""))
        console.print(f"   [bold green][OK] Perangkat Gateway Terdeteksi:[/bold green] [bold white]{gw_dev['ip']}[/bold white] | Tipe: [magenta]{dev_type}[/magenta] | Vendor: [bold cyan]{gw_dev['vendor']}[/bold cyan] | Ports: {gw_dev['open_ports']}")
        
        # Only inspect gateway deeply if requested
        if deep_inspect:
            adapter = gw_dev["adapter"]
            authenticated_gw = False
            gw_creds = get_vendor_prioritized_credentials(gw_dev.get("vendor", ""), ip_or_mac=gw_dev.get("ip"))
            with console.status("[cyan]Mencoba login kredensial ke gateway...[/cyan]"):
                for u, p in gw_creds:
                    success, msg = adapter.login(u, p)
                    if success:
                        authenticated_gw = True
                        console.print(f"   [bold green][OK] Login Sukses ke Gateway:[/bold green] User: [bold white]{u}[/bold white] / Password: [bold white]{p}[/bold white]")
                        break
                    elif "Rate-Limit" in msg:
                        console.print(f"   [yellow][!] Gateway 192.168.1.1 sedang dalam proteksi rate-limit ONT (tunggu ~60 detik cooldown).[/yellow]")
                        break
            
            if authenticated_gw:
                wan_info = adapter.get_wan_info()
                console.print("\n[bold cyan]=== STATUS WAN / JARINGAN GATEWAY LOKAL ===[/bold cyan]")
                console.print(f"   Mode Koneksi     : [bold white]{wan_info.get('mode') or 'Bridge / Direct'}[/bold white]")
                if wan_info.get('connection_name'):
                    console.print(f"   Nama Koneksi     : [bold white]{wan_info.get('connection_name')}[/bold white]")
                console.print(f"   IP WAN / Lokal   : [bold white]{wan_info.get('wan_ip') or 'Tidak terdeteksi / Bridge'}[/bold white]")
                console.print(f"   Gateway MikroTik : [bold white]{wan_info.get('wan_gateway') or 'Tidak terdeteksi'}[/bold white]")
                console.print(f"   Subnet Distribusi: [bold green]{wan_info.get('wan_subnet') or 'Tidak terdeteksi'}[/bold green]")
                if wan_info.get('vlan'):
                    console.print(f"   VLAN ID          : [yellow]{wan_info.get('vlan')}[/yellow]")
                
                pppoe_user = wan_info.get('pppoe_user')
                pppoe_pass = wan_info.get('pppoe_password')
                if pppoe_user:
                    pass_str = f" | Pass: [bold magenta]{pppoe_pass}[/bold magenta]" if pppoe_pass else ""
                    console.print(f"   Akun PPPoE       : [bold yellow]{pppoe_user}[/bold yellow]{pass_str}")
                else:
                    conn_name = wan_info.get('connection_name') or ''
                    if 'OMCI' in conn_name or 'TR069' in conn_name or wan_info.get('mode') == 'PPPoE':
                        console.print(f"   Akun PPPoE       : [yellow][Dikelola Otomatis / Diproteksi OLT OMCI][/yellow]")
                    else:
                        console.print(f"   Akun PPPoE       : [dim]Mode Bridge (Dial PPPoE berada di MikroTik / Router PC)[/dim]")
            else:
                console.print("   [yellow][!] Tidak dapat login ke web gateway (kredensial berbeda/terkunci).[/yellow]")
    else:
        console.print(f"   [red][-] Gateway {gw_ip} tidak merespon di port web manajemen.[/red]")

    # Subnet Class Discovery & Selection
    with console.status("[cyan]Menganalisis gateway & subnet routing jaringan...[/cyan]"):
        detected_subnets = get_all_detected_gateways_and_subnets(wan_info)
    
    console.print(f"\n[bold yellow]2. Pilihan Gateway & Subnet Jaringan untuk Scanning:[/bold yellow]")
    print_subnet_choices(detected_subnets)

    default_subnet = detected_subnets[0]["subnet"] if detected_subnets else "192.168.1.0/24"

    console.print(
        f"   [dim]Petunjuk: Tekan Enter/[cyan]1[/cyan] ({default_subnet}), [cyan]1,2[/cyan] (multi), [cyan]A[/cyan] (semua), atau ketik Subnet CIDR langsung.[/dim]"
    )

    user_input = Prompt.ask(
        "   Pilih nomor / Masukkan Gateway / Subnet",
        default="1"
    )

    chosen_entries = parse_target_network_input(user_input, detected_subnets, default_gw=gw_ip)
    chosen_subnets = [e["subnet"] for e in chosen_entries]

    # Fast Scan Selected Subnets
    console.print(f"\n[bold yellow]3. Memulai Scanning Host & Port pada Subnet:[/bold yellow] [bold cyan]{', '.join(chosen_subnets)}[/bold cyan]...")
    
    raw_devices = []
    if gw_dev:
        raw_devices.append(gw_dev)

    for sub in chosen_subnets:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            scan_task = progress.add_task(f"[cyan]Scan {sub}...", total=100)

            def scan_callback(completed, total, device):
                progress.update(scan_task, completed=int((completed / total) * 100))
                if device and not any(x['ip'] == device['ip'] for x in raw_devices):
                    d_type = device.get('device_type') or get_device_category(device.get('vendor', ''))
                    console.print(f"   [bold green][+][/bold green] [bold white]{device['ip']}[/bold white] | [cyan]{device['vendor']}[/cyan] ({d_type})")

            devices = scan_network(sub, max_threads=30, callback=scan_callback)
            for d in devices:
                if not any(x['ip'] == d['ip'] for x in raw_devices):
                    raw_devices.append(d)

    if not raw_devices:
        console.print("\n[bold red]Tidak ada ONT / perangkat aktif yang terdeteksi di subnet ini.[/bold red]")
        return [], gw_ip

    if not deep_inspect:
        # Fast mode: Return discovered devices immediately without waiting for brute force login
        return raw_devices, gw_ip

    # Deep inspection ONLY for Option [8] (Inventarisasi Lengkap)
    console.print(f"\n[bold yellow]Memeriksa login & membaca status detail dari {len(raw_devices)} perangkat yang ditemukan...[/bold yellow]")
    inspected_devices = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        insp_task = progress.add_task("[cyan]Autentikasi & ekstraksi detail...", total=len(raw_devices))

        def insp_callback(completed, total, dev_item):
            progress.update(insp_task, completed=completed, total=total)

        inspected_devices = run_batch_device_inspection(raw_devices, custom_creds=creds, max_workers=35, callback=insp_callback)

    # Android Alert / Terminal Bell (\a) when 100% complete
    print("\a", end="", flush=True)

    return inspected_devices, gw_ip

def filter_target_devices(devices_list, user_input_str):
    clean = user_input_str.strip()
    if clean.upper() == "A" or not clean:
        return devices_list
    
    # Range of indices: 1-4
    if "-" in clean and "." not in clean:
        try:
            start, end = clean.split("-", 1)
            s_idx = int(start.strip()) - 1
            e_idx = int(end.strip())
            return devices_list[max(0, s_idx):min(len(devices_list), e_idx)]
        except Exception:
            pass

    # Comma separated indices: 1,2,5
    if "," in clean and "." not in clean:
        res = []
        for part in clean.split(","):
            part = part.strip()
            if part.isdigit():
                idx = int(part) - 1
                if 0 <= idx < len(devices_list):
                    res.append(devices_list[idx])
        return res if res else devices_list

    # Single index
    if clean.isdigit():
        idx = int(clean) - 1
        if 0 <= idx < len(devices_list):
            return [devices_list[idx]]

    # IP range: 192.168.1.5-192.168.1.20
    if "-" in clean and "." in clean:
        try:
            start_ip, end_ip = clean.split("-", 1)
            import ipaddress
            s_int = int(ipaddress.IPv4Address(start_ip.strip()))
            e_int = int(ipaddress.IPv4Address(end_ip.strip()))
            matched = []
            for d in devices_list:
                d_int = int(ipaddress.IPv4Address(d["ip"]))
                if s_int <= d_int <= e_int:
                    matched.append(d)
            if matched:
                return matched
        except Exception:
            pass

    # Exact single IP match
    matched = [d for d in devices_list if d["ip"] == clean]
    if matched:
        return matched

    return devices_list

def run_interactive():
    print_banner()
    creds = get_credentials()
    cached_devices = None
    cached_gw_ip = None
    cached_is_deep = False

    while True:
        console.print("\n[bold yellow]MENU UTAMA - PILIH KEBUTUHAN / TINDAKAN:[/bold yellow]")
        console.print("   [1] Penetration Testing & Audit Kerentanan Jaringan")
        console.print("   [2] Deteksi Rogue DHCP Server di Jaringan LAN")
        console.print("   [3] Batch Ubah Konfigurasi WAN (PPPoE / VLAN / TR-069)")
        console.print("   [4] Batch Multi-SSID / Wi-Fi (Tambah/Ubah SSID & Password)")
        console.print("   [5] Batch Kontrol Port LAN (Aktifkan / Matikan Port LAN)")
        console.print("   [6] Batch Ganti Password Admin / Kredensial ONT")
        console.print("   [7] Audit / Uji Login Kredensial ONT Saja")
        console.print("   [8] Scan & Inventarisasi Perangkat ONT (Status Detail & Ekspor)")
        console.print("   [9] Batch Reboot ONT")
        console.print("   [10] Manajemen Password & Kamus Kredensial")
        console.print("   [11] Batch Anti-Reset ONT (Kunci Konfigurasi ke ROM & Kunci Tombol Reset Fisik)")
        console.print("   [12] Ubah Username & Password Master Aplikasi (Keamanan Engine)")
        console.print("   [0] Keluar")

        choice = Prompt.ask("\n   Pilihan Anda", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"], default="1")

        if choice == "0":
            console.print("[dim]Terima kasih. Program selesai.[/dim]")
            break

        if choice == "2":
            # Deteksi Rogue DHCP Server directly without scanning ONTs
            gw = get_default_gateway()
            gw_ip = gw['gateway_ip'] if gw else "192.168.1.1"
            console.print(f"\n[bold yellow]Memulai Pemindaian Rogue DHCP Server pada Jaringan LAN...[/bold yellow]")
            console.print("   [dim]Mengirim paket DHCP Discover broadcast ke 255.255.255.255:67...[/dim]")
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
                dhcp_task = progress.add_task("[cyan]Mendengarkan respon DHCP Server (3.5 detik)...", total=None)
                rogue_list = detect_rogue_dhcp_servers(timeout=3.5)
            
            if not rogue_list:
                console.print("\n[bold green][OK] Tidak ada DHCP Server liar yang terdeteksi di segmen jaringan ini.[/bold green]")
            else:
                if is_mobile_term():
                    console.print("\n[bold red]Daftar DHCP Server yang Merespon:[/bold red]")
                    for idx, srv in enumerate(rogue_list, 1):
                        is_legit_gw = (srv["server_ip"] == gw_ip)
                        badge = "[bold green][LEGIT GATEWAY][/bold green]" if is_legit_gw else "[bold red][ROGUE DHCP][/bold red]"
                        console.print(f"  [{idx}] Server: [bold white]{srv['server_ip']}[/bold white] | Lease: {srv.get('offered_ip') or '-'} {badge}")
                else:
                    dhcp_table = Table(title="Daftar DHCP Server yang Merespon di LAN", border_style="red")
                    dhcp_table.add_column("No", justify="center", style="dim")
                    dhcp_table.add_column("IP Server DHCP", style="bold white")
                    dhcp_table.add_column("IP yang Ditawarkan (Lease)", style="yellow")
                    dhcp_table.add_column("Status Verifikasi", justify="center")
                    
                    for idx, srv in enumerate(rogue_list, 1):
                        is_legit_gw = (srv["server_ip"] == gw_ip)
                        status_badge = "[bold green]GATEWAY UTAMA (LEGIT)[/bold green]" if is_legit_gw else "[bold red][ROGUE] DHCP LIAR[/bold red]"
                        dhcp_table.add_row(str(idx), srv["server_ip"], srv.get("offered_ip") or "-", status_badge)
                    console.print(dhcp_table)

                rogue_found = any(s["server_ip"] != gw_ip for s in rogue_list)
                if rogue_found:
                    console.print(Panel(
                        "[bold red]PERINGATAN KEAMANAN KRITIS:[/bold red]\n"
                        "Terdeteksi server DHCP liar (Rogue DHCP) yang aktif di jaringan Anda!\n"
                        "Hal ini dapat menyebabkan IP conflict dan memutuskan koneksi internet pelanggan lain.\n"
                        "Segera aktifkan [bold white]DHCP Snooping[/bold white] di Switch/OLT atau isolasi port pelanggan terkait.",
                        title="[bold red][ALERT] ROGUE DHCP DETECTED[/bold red]",
                        border_style="red"
                    ))
            continue

        if choice == "10":
            # Password Management
            console.print("\n[bold yellow]Manajemen Password Kredensial ONT / Router[/bold yellow]")
            custom_saved = load_custom_passwords()
            creds = get_credentials()
            console.print(f"   [dim]{len(creds)} kombinasi login aktif ({len(custom_saved)} password kustom tersimpan di {DEFAULT_PASSWORDS_FILE})[/dim]")
            
            if custom_saved:
                console.print("   [bold cyan]Password Kustom Saat Ini:[/bold cyan]")
                for u, p in custom_saved:
                    console.print(f"     - {u}:{p}")
            
            if Confirm.ask("\n   Tambah password baru ke kamus?", default=True):
                console.print("   [cyan]Masukkan password (bisa dipisah koma, spasi, atau baris baru). Format: username:password atau password saja[/cyan]")
                new_pass_input = Prompt.ask("   Daftar Password Baru")
                if new_pass_input.strip():
                    new_pairs = []
                    for item in new_pass_input.replace("\n", ",").split(","):
                        item = item.strip()
                        if item:
                            if ":" in item:
                                u, p = item.split(":", 1)
                                new_pairs.append((u.strip(), p.strip()))
                            else:
                                new_pairs.append(("admin", item))
                                new_pairs.append(("", item))
                                new_pairs.append(("user", item))
                    
                    updated_list = new_pairs + custom_saved
                    save_custom_passwords(updated_list)
                    creds = get_credentials()
                    console.print(f"   [bold green][OK] {len(new_pairs)} password berhasil disimpan permanen ke {DEFAULT_PASSWORDS_FILE}![/bold green]")
            continue

        if choice == "12":
            change_master_credentials()
            continue

        # Need deep inspection ONLY if choice == '8'
        is_deep_action = (choice == "8")

        # Scan if cache is empty, or if choice 8 needs deep inspection but cache is not deep, or user requests rescan
        needs_scan = (cached_devices is None) or (is_deep_action and not cached_is_deep)
        if needs_scan or Confirm.ask("\nLakukan scanning ulang subnet jaringan?", default=False):
            cached_devices, cached_gw_ip = run_discovery_and_scan(creds, deep_inspect=is_deep_action)
            cached_is_deep = is_deep_action
            if not cached_devices:
                continue

        target_pool = cached_devices
        gw_ip = cached_gw_ip

        # Display discovered devices
        print_device_table(target_pool, is_deep=is_deep_action)

        if choice == "8":
            # Auto-export to inventory_result.json & inventory_result.csv in Termux storage / output
            j_file, c_file = export_inventory_reports(target_pool, json_filename="inventory_result.json", csv_filename="inventory_result.csv")
            console.print(f"\n[bold green][OK] Hasil inventarisasi otomatis diekspor ke:[/bold green]")
            console.print(f"   - JSON : [bold cyan]{j_file}[/bold cyan]")
            console.print(f"   - CSV  : [bold cyan]{c_file}[/bold cyan]")
            continue

        # Target selection for action
        console.print(
            f"\n[bold yellow]Pilih Target ONT untuk Tindakan Ini:[/bold yellow]\n"
            f"   [dim]Ketik [cyan]A[/cyan] untuk Semua ({len(target_pool)} ONT), nomor ([cyan]1,2[/cyan] atau [cyan]1-4[/cyan]), atau rentang IP.[/dim]"
        )
        target_input = Prompt.ask("   Target ONT", default="A")
        target_devices = filter_target_devices(target_pool, target_input)
        console.print(f"   [bold green][OK] {len(target_devices)} unit ONT terpilih sebagai target eksekusi.[/bold green]")

        if not target_devices:
            console.print("[yellow]Tidak ada target yang terpilih.[/yellow]")
            continue

        # Optional custom credentials for execution
        custom_pass_input = Prompt.ask("   Tambahan password kustom (pisahkan koma jika ada, atau kosongkan)", default="")
        custom_creds = None
        if custom_pass_input.strip():
            user_list = [("admin", p.strip()) for p in custom_pass_input.split(",") if p.strip()]
            user_list += [("", p.strip()) for p in custom_pass_input.split(",") if p.strip()]
            custom_creds = user_list + get_credentials()

        if choice == "1":
            # Penetration Testing & Vulnerability Audit
            console.print(f"\n[bold yellow]Menjalankan Penetration Testing & Audit Kerentanan pada {len(target_devices)} ONT...[/bold yellow]")
            console.print("   [dim]Target: Default SuperAdmin Creds, Telnet Root Shell, Open DNS, SNMP Public, Open Ports[/dim]\n")
            
            pentest_results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                pt_task = progress.add_task("[cyan]Audit kerentanan...", total=100)
                
                def pt_cb(completed, total, res):
                    progress.update(pt_task, completed=int((completed / total) * 100))
                    risk_badge = f"[{res['risk_color']}][{res['risk_level']}][/{res['risk_color']}]"
                    vuln_info = f"({res['vuln_count']} celah)" if res['vuln_count'] > 0 else "(Aman)"
                    console.print(f"   {risk_badge} [bold white]{res['ip']}[/bold white] {res['vendor']} — {vuln_info}")
                
                pentest_results = run_batch_pentest(target_devices, custom_creds=custom_creds, max_workers=15, callback=pt_cb)

            print_pentest_results(pentest_results)

            if Confirm.ask("\nSimpan laporan hasil Penetration Testing ke file?", default=True):
                pt_export = Prompt.ask("   Format ekspor [1] CSV / [2] JSON", choices=["1", "2"], default="1")
                if pt_export == "1":
                    pt_csv_file = "laporan_pentest_ont.csv"
                    with open(pt_csv_file, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["IP", "Vendor", "MAC", "Risk Level", "Risk Score", "Default User", "Default Pass", "Telnet Root", "Open DNS", "SNMP Public", "Open Ports", "Vulnerabilities"])
                        for r in pentest_results:
                            vuln_names = "; ".join([v["name"] for v in r["vulnerabilities"]])
                            t_root = r["telnet_backdoors"][0] if r["telnet_backdoors"] else ""
                            writer.writerow([
                                r["ip"], r["vendor"], r["mac"], r["risk_level"], r["risk_score"],
                                r["active_user"] or "", r["active_pass"] or "",
                                f"{t_root[0]}:{t_root[1]}" if t_root else "",
                                r["is_open_dns"], r["is_snmp_exposed"],
                                ",".join(map(str, r["open_ports"])),
                                vuln_names
                            ])
                    console.print(f"[bold green][OK] Laporan CSV tersimpan di {pt_csv_file}[/bold green]")
                else:
                    pt_json_file = "laporan_pentest_ont.json"
                    with open(pt_json_file, "w", encoding="utf-8") as f:
                        json.dump(pentest_results, f, indent=2)
                    console.print(f"[bold green][OK] Laporan JSON tersimpan di {pt_json_file}[/bold green]")
            continue

        elif choice == "3":
            # WAN Configuration Parameters
            console.print("\n[bold yellow]Parameter Konfigurasi WAN Massal:[/bold yellow]")
            mode = Prompt.ask("   Mode WAN", choices=["PPPoE", "DHCP", "Bridge"], default="PPPoE")
            vlan = Prompt.ask("   VLAN ID (Kosongkan untuk mempertahankan VLAN lama modem)", default="")
            
            pppoe_user = ""
            pppoe_pass = ""
            if mode == "PPPoE":
                console.print("   [dim]Tips: Gunakan {ip_last} untuk otomatis memakai angka octet terakhir IP (misal: user_{ip_last})[/dim]")
                pppoe_user = Prompt.ask("   PPPoE Username", default="user_{ip_last}")
                pppoe_pass = Prompt.ask("   PPPoE Password", default="123456")

            tr069_url = ""
            if Confirm.ask("   Konfigurasi / Update TR-069 Server ACS URL?", default=False):
                tr069_url = Prompt.ask("   TR-069 ACS URL (contoh: http://acs.domainisp.com:7547)")

            wan_config = {
                "mode": mode,
                "vlan_id": vlan,
                "pppoe_username": pppoe_user,
                "pppoe_password": pppoe_pass,
                "tr069_url": tr069_url,
            }

            console.print(f"\n[bold yellow]Menjalankan Proses Eksekusi Perintah WAN pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                exec_task = progress.add_task("[cyan]Proses WAN...", total=100)

                def exec_cb(completed, total, res):
                    progress.update(exec_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["wan_updated"] else ("[-]" if res["login_success"] else "[FAIL]")
                    color = "green" if res["wan_updated"] else ("yellow" if res["login_success"] else "red")
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_provisioning(target_devices, wan_config, custom_creds, max_workers=60, callback=exec_cb)

            print_execution_summary(results, choice)

        elif choice == "4":
            # Multi-SSID / Wi-Fi Configuration
            console.print("\n[bold yellow]Parameter Konfigurasi Wi-Fi Multi-SSID Massal:[/bold yellow]")
            ssid_idx = Prompt.ask("   Index SSID", choices=["1", "2", "3", "4"], default="1")
            ssid_name = Prompt.ask("   Nama SSID (Wi-Fi Name)", default=f"LITCH_WIFI_{{ip_last}}")
            auth_mode = Prompt.ask("   Tipe Enkripsi / Keamanan", choices=["WPA2-PSK", "WPA/WPA2-PSK", "Open"], default="WPA2-PSK")
            
            wlan_pwd = ""
            if auth_mode != "Open":
                wlan_pwd = Prompt.ask("   Password Wi-Fi", default="litch12345")

            hide_ssid = Confirm.ask("   Sembunyikan SSID (Hide SSID)?", default=False)
            enable_wlan = Confirm.ask(f"   Aktifkan SSID{ssid_idx} ini?", default=True)

            wlan_config = {
                "ssid_index": int(ssid_idx),
                "enable": enable_wlan,
                "ssid_name": ssid_name,
                "auth_mode": auth_mode,
                "password": wlan_pwd,
                "hide_ssid": hide_ssid,
            }

            console.print(f"\n[bold yellow]Menjalankan Proses Konfigurasi Wi-Fi pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                wlan_task = progress.add_task("[cyan]Proses Wi-Fi...", total=100)

                def wlan_cb(completed, total, res):
                    progress.update(wlan_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["wlan_updated"] else ("[-]" if res["login_success"] else "[FAIL]")
                    color = "green" if res["wlan_updated"] else ("yellow" if res["login_success"] else "red")
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_wlan_config(target_devices, wlan_config, custom_creds, max_workers=60, callback=wlan_cb)

            print_execution_summary(results, choice)

        elif choice == "5":
            # Batch LAN Port Control
            console.print("\n[bold yellow]Parameter Kontrol Port LAN Massal:[/bold yellow]")
            lan1 = Confirm.ask("   Port LAN 1 Aktif?", default=True)
            lan2 = Confirm.ask("   Port LAN 2 Aktif?", default=True)
            lan3 = Confirm.ask("   Port LAN 3 Aktif?", default=True)
            lan4 = Confirm.ask("   Port LAN 4 Aktif?", default=True)

            lan_config = {
                "enable": True,
                "ports": {
                    "lan1": lan1,
                    "lan2": lan2,
                    "lan3": lan3,
                    "lan4": lan4,
                }
            }

            console.print(f"\n[bold yellow]Menjalankan Kontrol Port LAN pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                lan_task = progress.add_task("[cyan]Proses Port LAN...", total=100)

                def lan_cb(completed, total, res):
                    progress.update(lan_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["lan_updated"] else ("[-]" if res["login_success"] else "[FAIL]")
                    color = "green" if res["lan_updated"] else ("yellow" if res["login_success"] else "red")
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_lan_config(target_devices, lan_config, custom_creds, max_workers=60, callback=lan_cb)

            print_execution_summary(results, choice)

        elif choice == "6":
            # Batch Password Change
            console.print("\n[bold yellow]Parameter Ganti Password Admin Massal:[/bold yellow]")
            target_user = Prompt.ask("   Username yang akan diubah", default="admin")
            new_pwd = Prompt.ask("   Password Baru", password=True)
            new_pwd_cfm = Prompt.ask("   Konfirmasi Password Baru", password=True)

            if new_pwd != new_pwd_cfm:
                console.print("[bold red]Konfirmasi password tidak cocok! Operasi dibatalkan.[/bold red]")
                continue

            if not new_pwd.strip():
                console.print("[bold red]Password baru tidak boleh kosong![/bold red]")
                continue

            if Confirm.ask("   Simpan password baru ini ke passwords.txt?", default=True):
                saved = load_custom_passwords()
                save_custom_passwords([(target_user, new_pwd)] + saved)
                console.print(f"   [green][OK] Password baru disimpan ke {DEFAULT_PASSWORDS_FILE}[/green]")

            console.print(f"\n[bold yellow]Menjalankan Proses Ganti Password pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                chg_task = progress.add_task("[cyan]Proses Ganti Password...", total=100)

                def chg_cb(completed, total, res):
                    progress.update(chg_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["password_changed"] else ("[-]" if res["login_success"] else "[FAIL]")
                    color = "green" if res["password_changed"] else ("yellow" if res["login_success"] else "red")
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_password_change(target_devices, new_pwd, target_username=target_user, custom_creds=custom_creds, max_workers=60, callback=chg_cb)

            print_execution_summary(results, choice)

        elif choice == "9":
            # Batch Reboot
            console.print(f"\n[bold red]Konfirmasi Reboot Massal:[/bold red]")
            console.print(f"   Target  : [bold white]{len(target_devices)} unit ONT[/bold white]")
            console.print(f"   [yellow]Semua konfigurasi yang sudah diubah akan diterapkan setelah ONT restart.[/yellow]")
            if not Confirm.ask("\n   Jalankan reboot sekarang?", default=True):
                console.print("[yellow]Operasi dibatalkan.[/yellow]")
                continue

            reboot_results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                reboot_task = progress.add_task("[cyan]Kirim perintah reboot...", total=100)
                def reboot_cb(completed, total, res):
                    progress.update(reboot_task, completed=int((completed / total) * 100))
                    ok = res.get("rebooted", False)
                    color = "green" if ok else ("yellow" if res["login_success"] else "red")
                    icon = "[OK]" if ok else ("[-]" if res["login_success"] else "[FAIL]")
                    console.print(f"   [{color}]{icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")
                reboot_results = run_batch_reboot(target_devices, custom_creds, max_workers=60, callback=reboot_cb)

            ok_count = sum(1 for r in reboot_results if r.get("rebooted"))
            console.print(Panel(
                f"[bold green]Berhasil Reboot  :[/bold green] {ok_count} ONT\n"
                + f"[bold red]Gagal / Tidak Respon:[/bold red] {len(reboot_results) - ok_count} ONT",
                title="[bold cyan]Ringkasan Batch Reboot[/bold cyan]", border_style="cyan"
            ))
            continue

        elif choice == "11":
            # Batch Anti-Reset: Burn Config to ROM & Lock Reset Button
            console.print("\n[bold yellow]Parameter Anti-Reset & Proteksi Konfigurasi Massal:[/bold yellow]")
            console.print("   [dim]Mengunci settingan agar tidak hilang saat modem ditusuk tombol reset fisik oleh pelanggan.[/dim]\n")

            set_pwd = Confirm.ask("   [1] Ganti / Set Password Admin ONT baru yang akan dikunci permanen?", default=True)
            target_user = "admin"
            new_pwd = ""
            if set_pwd:
                target_user = Prompt.ask("       Username admin target", default="admin")
                new_pwd = Prompt.ask("       Password Baru", password=True)
                new_pwd_cfm = Prompt.ask("       Konfirmasi Password Baru", password=True)
                if new_pwd != new_pwd_cfm:
                    console.print("[bold red]Konfirmasi password tidak cocok! Operasi dibatalkan.[/bold red]")
                    continue
                if not new_pwd.strip():
                    console.print("[bold red]Password tidak boleh kosong![/bold red]")
                    continue
                if Confirm.ask("       Simpan password baru ini ke passwords.txt?", default=True):
                    saved = load_custom_passwords()
                    save_custom_passwords([(target_user, new_pwd)] + saved)
                    console.print(f"       [green][OK] Password baru disimpan ke {DEFAULT_PASSWORDS_FILE}[/green]")

            burn_def = Confirm.ask("   [2] Jadikan konfigurasi & password ini sebagai Factory Default ROM (Burn to ROM)?", default=True)
            lock_btn = Confirm.ask("   [3] Kunci / Nonaktifkan fungsi tombol Reset fisik (Disable Hardware Reset Button)?", default=True)

            lock_config = {
                "set_new_password": set_pwd,
                "target_username": target_user,
                "new_password": new_pwd,
                "burn_default_config": burn_def,
                "disable_reset_button": lock_btn,
            }

            console.print(f"\n[bold yellow]Menjalankan Proses Penguncian Anti-Reset pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                lock_task = progress.add_task("[cyan]Kunci Anti-Reset...", total=100)

                def lock_cb(completed, total, res):
                    progress.update(lock_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["anti_reset_locked"] else ("[-]" if res["login_success"] else "[FAIL]")
                    color = "green" if res["anti_reset_locked"] else ("yellow" if res["login_success"] else "red")
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_anti_reset(target_devices, lock_config, custom_creds, max_workers=60, callback=lock_cb)

            print_execution_summary(results, choice)

        else:
            # Audit / Credential Check Only (Option 7)
            console.print(f"\n[bold yellow]Menjalankan Pengujian Login pada {len(target_devices)} ONT...[/bold yellow]")
            results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                audit_task = progress.add_task("[cyan]Uji login...", total=100)

                def audit_cb(completed, total, res):
                    progress.update(audit_task, completed=int((completed / total) * 100))
                    status_icon = "[OK]" if res["login_success"] else "[FAIL]"
                    color = "green" if res["login_success"] else "red"
                    console.print(f"   [{color}]{status_icon} [{res['ip']}][/{color}] {res['vendor']} — {res['message']}")

                results = run_batch_provisioning(target_devices, None, custom_creds, max_workers=15, callback=audit_cb)

            print_execution_summary(results, choice)

        # Export option
        if Confirm.ask("\nSimpan hasil laporan eksekusi ke file CSV?", default=False):
            csv_file = "laporan_ont_provisioning.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Vendor", "Login Status", "Username", "Password", "Action Status", "Message"])
                for r in results:
                    action_stat = (
                        r.get("wan_updated") if choice == "3" else
                        (r.get("wlan_updated") if choice == "4" else
                        (r.get("lan_updated") if choice == "5" else
                        (r.get("password_changed") if choice == "6" else
                        (r.get("anti_reset_locked") if choice == "11" else "-"))))
                    )
                    writer.writerow([r["ip"], r["vendor"], r["login_success"], r["username_used"], r["password_used"], action_stat, r["message"]])
            console.print(f"[bold green][OK] Laporan CSV tersimpan di {csv_file}[/bold green]")

        # Interactive loop prompt
        another = Confirm.ask("\n[bold cyan]Apakah Anda ingin melakukan tindakan lain?[/bold cyan]", default=True)
        if not another:
            console.print("[dim]Terima kasih. Program selesai.[/dim]")
            break

def main():
    # Security Guard: Require master owner authentication before running tools
    require_authentication()

    parser = argparse.ArgumentParser(description="Multi-Vendor ONT & SOHO Router Management Engine (Fast CLI)")
    parser.add_argument("-t", "--target", help="Target IP tunggal (contoh: 192.168.1.1). Default otomatis deteksi Default Gateway.", default=None)
    parser.add_argument("--subnet", nargs="?", const="auto", help="Scan seluruh rentang subnet IP /24 (contoh: --subnet atau --subnet 192.168.1.0/24)", default=None)
    parser.add_argument("--scan", help="Alias untuk --subnet CIDR", default=None)
    parser.add_argument("--inventory", action="store_true", help="Jalankan inventarisasi multi-vendor (PPPoE, SN, VLAN) dan auto-export JSON/CSV")
    parser.add_argument("--pentest", action="store_true", help="Jalankan Penetration Testing & Vulnerability Audit pada target")
    parser.add_argument("--anti-reset", action="store_true", help="Kunci konfigurasi permanen ke ROM default & kunci tombol reset fisik (Anti-Reset)")
    parser.add_argument("--rogue-dhcp", action="store_true", help="Deteksi Rogue DHCP Server di jaringan lokal")
    parser.add_argument("--mode", choices=["PPPoE", "DHCP", "Bridge"], default="PPPoE", help="Mode WAN")
    parser.add_argument("--vlan", help="VLAN ID", default="")
    parser.add_argument("--pppoe-user", help="Username PPPoE (bisa pakai {ip_last})", default="")
    parser.add_argument("--pppoe-pass", help="Password PPPoE", default="")
    parser.add_argument("--tr069", help="URL Server TR-069 GenieACS", default="")
    parser.add_argument("--custom-creds", help="File JSON/Text custom credentials", default=None)
    parser.add_argument("--threads", type=int, default=100, help="Jumlah worker paralel (default: 100)")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        # Default interactive mode
        run_interactive()
    elif args.rogue_dhcp:
        console.print("[cyan]Mencari Rogue DHCP Server pada interface lokal...[/cyan]")
        rogues = detect_rogue_dhcp_servers(timeout=3.0)
        if rogues:
            console.print(f"[bold red]Ditemukan {len(rogues)} DHCP Server:[/bold red]")
            for r in rogues:
                console.print(f"  [+] Server IP: {r['server_ip']} | Offered IP: {r['offered_ip']}")
        else:
            console.print("[green][OK] Tidak ada Rogue DHCP Server yang merespon.[/green]")
    elif args.inventory:
        custom_creds = get_credentials(args.custom_creds)
        target_subnet = args.subnet if (args.subnet and args.subnet != "auto") else (args.scan or None)
        
        if args.target:
            console.print(f"[cyan]Menargetkan IP Tunggal: [bold white]{args.target}[/bold white]...[/cyan]")
            dev = scan_host(args.target)
            devices = [dev] if dev else []
        elif target_subnet:
            console.print(f"[cyan]Memindai seluruh subnet: [bold white]{target_subnet}[/bold white]...[/cyan]")
            devices = scan_network(target_subnet, max_threads=args.threads)
        else:
            gw = get_default_gateway()
            gw_ip = gw['gateway_ip'] if gw else "192.168.1.1"
            console.print(f"[cyan]Deteksi Instan Default Gateway: [bold white]{gw_ip}[/bold white]...[/cyan]")
            dev = scan_host(gw_ip)
            devices = [dev] if dev else []

        if not devices:
            console.print("[red]Tidak ada perangkat yang terdeteksi.[/red]")
            return

        console.print(f"[green]Ditemukan {len(devices)} perangkat. Menginspeksi kredensial & PPPoE...[/green]")
        inspected = run_batch_device_inspection(devices, custom_creds=custom_creds, max_workers=args.threads)
        print_device_table(inspected, is_deep=True)
        j_f, c_f = export_inventory_reports(inspected)
        console.print(f"\n[bold green][OK] Selesai! Laporan tersimpan di:[/bold green]")
        console.print(f"   - JSON : [bold cyan]{j_f}[/bold cyan]")
        console.print(f"   - CSV  : [bold cyan]{c_f}[/bold cyan]")
        print("\a", end="", flush=True)
    elif args.pentest:
        target_subnet = args.subnet if (args.subnet and args.subnet != "auto") else (args.scan or get_default_local_subnet())
        console.print(f"[cyan]Scanning network {target_subnet} untuk Penetration Testing...[/cyan]")
        devices = scan_network(target_subnet, max_threads=args.threads)
        console.print(f"[green]Ditemukan {len(devices)} unit ONT. Memulai Security Audit...[/green]")
        custom_creds = get_credentials(args.custom_creds)
        pentest_results = run_batch_pentest(devices, custom_creds, max_workers=args.threads)
        console.print(json.dumps(pentest_results, indent=2))
        print("\a", end="", flush=True)
    elif args.anti_reset:
        target_subnet = args.subnet if (args.subnet and args.subnet != "auto") else (args.scan or get_default_local_subnet())
        console.print(f"[cyan]Scanning network {target_subnet} untuk Batch Anti-Reset...[/cyan]")
        devices = scan_network(target_subnet, max_threads=args.threads)
        console.print(f"[green]Ditemukan {len(devices)} unit ONT. Mengunci konfigurasi ROM & Reset Key...[/green]")
        custom_creds = get_credentials(args.custom_creds)
        lock_cfg = {"burn_default_config": True, "disable_reset_button": True}
        lock_results = run_batch_anti_reset(devices, lock_cfg, custom_creds, max_workers=args.threads)
        console.print(json.dumps([{"ip": r["ip"], "login": r["login_success"], "anti_reset_locked": r["anti_reset_locked"], "msg": r["message"]} for r in lock_results], indent=2))
        print("\a", end="", flush=True)
    else:
        target_subnet = args.subnet if (args.subnet and args.subnet != "auto") else (args.scan or get_default_local_subnet())
        console.print(f"[cyan]Scanning network {target_subnet}...[/cyan]")
        devices = scan_network(target_subnet, max_threads=args.threads)
        console.print(f"[green]Ditemukan {len(devices)} unit ONT.[/green]")

        wan_config = None
        if args.pppoe_user or args.vlan or args.tr069:
            wan_config = {
                "mode": args.mode,
                "vlan_id": args.vlan,
                "pppoe_username": args.pppoe_user,
                "pppoe_password": args.pppoe_pass,
                "tr069_url": args.tr069,
            }

        custom_creds = get_credentials(args.custom_creds)
        results = run_batch_provisioning(devices, wan_config, custom_creds, max_workers=args.threads)
        console.print(json.dumps([{"ip": r["ip"], "login": r["login_success"], "wan": r["wan_updated"], "msg": r["message"]} for r in results], indent=2))
        print("\a", end="", flush=True)

if __name__ == "__main__":
    main()
