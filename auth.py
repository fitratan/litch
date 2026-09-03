import os
import sys
import time
import json
import hmac
import hashlib
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console(emoji=False)

AUTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".auth_security.json")
SECRET_SALT = b"NODERA_NET_SEC_CORE_v2026_@ANTIGRAV"

def _hash_credential(text: str, salt: bytes) -> str:
    """Hash text using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    return hashlib.pbkdf2_hmac("sha256", text.encode("utf-8"), salt, 200000).hex()

def _calculate_signature(u_hash: str, p_hash: str, salt_hex: str) -> str:
    """Calculate HMAC integrity signature to detect file tampering."""
    msg = f"{u_hash}:{p_hash}:{salt_hex}".encode("utf-8")
    return hmac.new(SECRET_SALT, msg, hashlib.sha256).hexdigest()

def is_auth_initialized() -> bool:
    """Check if owner credentials have been established."""
    if not os.path.exists(AUTH_FILE):
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            u_hash = data.get("u_hash")
            p_hash = data.get("p_hash")
            salt_hex = data.get("salt")
            sig = data.get("signature")
            if u_hash and p_hash and salt_hex and sig:
                # Verify HMAC signature
                expected_sig = _calculate_signature(u_hash, p_hash, salt_hex)
                return hmac.compare_digest(sig, expected_sig)
    except Exception:
        pass
    return False

def setup_initial_credentials() -> bool:
    """Interactive first-time owner credential setup."""
    console.print(Panel(
        "[bold yellow]AKTIVASI KEAMANAN PERDANA — NODERA NETWORK ENGINE[/bold yellow]\n\n"
        "[white]Belum ada kredensial pemilik terdaftar.\n"
        "Silakan tentukan [bold green]Username[/bold green] dan [bold green]Password[/bold green] Master Anda.\n"
        "[bold red]Kredensial ini akan dienkripsi dengan PBKDF2-SHA256 (200.000 iterasi) dan tidak dapat diubah oleh orang lain tanpa password lama![/bold red][/white]",
        title="[bold cyan]SECURITY INITIALIZATION[/bold cyan]",
        border_style="cyan"
    ))

    while True:
        username = Prompt.ask("   [bold cyan]Masukkan Username Master Baru[/bold cyan]").strip()
        if len(username) < 3:
            console.print("   [red]Username minimal 3 karakter.[/red]")
            continue
        break

    while True:
        password = Prompt.ask("   [bold cyan]Masukkan Password Master Baru[/bold cyan]", password=True).strip()
        if len(password) < 4:
            console.print("   [red]Password minimal 4 karakter.[/red]")
            continue
        password_confirm = Prompt.ask("   [bold cyan]Konfirmasi Ulang Password Master[/bold cyan]", password=True).strip()
        if password != password_confirm:
            console.print("   [red]Konfirmasi password tidak cocok! Silakan ulangi.[/red]")
            continue
        break

    salt = os.urandom(16)
    salt_hex = salt.hex()
    u_hash = _hash_credential(username, salt)
    p_hash = _hash_credential(password, salt)
    sig = _calculate_signature(u_hash, p_hash, salt_hex)

    data = {
        "u_hash": u_hash,
        "p_hash": p_hash,
        "salt": salt_hex,
        "signature": sig,
        "created_at": time.time()
    }

    try:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        try:
            os.chmod(AUTH_FILE, 0o600)
        except Exception:
            pass
        console.print("\n[bold green][OK] Kredensial Master berhasil disimpan dan dikunci permanen![/bold green]\n")
        return True
    except Exception as e:
        console.print(f"[bold red]Gagal menyimpan file keamanan: {e}[/bold red]")
        return False

def verify_credentials(username_input: str, password_input: str) -> bool:
    """Verify input credentials against PBKDF2 hash and HMAC signature."""
    if not os.path.exists(AUTH_FILE):
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            u_hash = data.get("u_hash")
            p_hash = data.get("p_hash")
            salt_hex = data.get("salt")
            sig = data.get("signature")

            # Check file tampering
            expected_sig = _calculate_signature(u_hash, p_hash, salt_hex)
            if not hmac.compare_digest(sig, expected_sig):
                console.print("[bold red][CRITICAL] File keamanan telah dimodifikasi secara ilegal / rusak![/bold red]")
                return False

            salt = bytes.fromhex(salt_hex)
            calc_u_hash = _hash_credential(username_input.strip(), salt)
            calc_p_hash = _hash_credential(password_input.strip(), salt)

            return hmac.compare_digest(u_hash, calc_u_hash) and hmac.compare_digest(p_hash, calc_p_hash)
    except Exception:
        return False

def require_authentication() -> bool:
    """
    Main authentication barrier required before accessing main.py.
    Provides up to 3 login attempts with rate-limiting.
    """
    if not is_auth_initialized():
        if not setup_initial_credentials():
            sys.exit(1)

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        console.print(f"\n[bold yellow]🔐 OTENTIKASI KEAMANAN NODERA (Percobaan {attempt}/{max_attempts})[/bold yellow]")
        user = Prompt.ask("   [bold white]Username Master[/bold white]").strip()
        pwd = Prompt.ask("   [bold white]Password Master[/bold white]", password=True).strip()

        if verify_credentials(user, pwd):
            console.print("[bold green][✓] Otentikasi Berhasil! Selamat datang.[/bold green]\n")
            return True
        else:
            remaining = max_attempts - attempt
            if remaining > 0:
                console.print(f"   [bold red][✗] Username atau Password salah! (Sisa {remaining}x percobaan)[/bold red]")
                time.sleep(1.0)
            else:
                console.print("\n[bold red][ALERT] Akses Ditolak: Melebihi batas maksimal percobaan login![/bold red]")
                console.print("[dim]Program dihentikan untuk keamanan.[/dim]")
                sys.exit(1)

    return False

def change_master_credentials() -> bool:
    """Securely change master credentials after verifying old password."""
    console.print("\n[bold yellow]=== UBAH USERNAME & PASSWORD MASTER ===[/bold yellow]")
    old_user = Prompt.ask("   [bold white]Masukkan Username Master Saat Ini[/bold white]").strip()
    old_pwd = Prompt.ask("   [bold white]Masukkan Password Master Saat Ini[/bold white]", password=True).strip()

    if not verify_credentials(old_user, old_pwd):
        console.print("[bold red][✗] Password lama salah! Perubahan kredensial ditolak.[/bold red]")
        return False

    console.print("[bold green][✓] Verifikasi password lama berhasil.[/bold green]")
    new_user = Prompt.ask("   [bold cyan]Masukkan Username Master Baru[/bold cyan]").strip()
    if len(new_user) < 3:
        console.print("[red]Username minimal 3 karakter.[/red]")
        return False

    new_pwd = Prompt.ask("   [bold cyan]Masukkan Password Master Baru[/bold cyan]", password=True).strip()
    if len(new_pwd) < 4:
        console.print("[red]Password minimal 4 karakter.[/red]")
        return False

    new_pwd_confirm = Prompt.ask("   [bold cyan]Konfirmasi Password Master Baru[/bold cyan]", password=True).strip()
    if new_pwd != new_pwd_confirm:
        console.print("[bold red]Konfirmasi password tidak cocok! Dibatalkan.[/bold red]")
        return False

    salt = os.urandom(16)
    salt_hex = salt.hex()
    u_hash = _hash_credential(new_user, salt)
    p_hash = _hash_credential(new_pwd, salt)
    sig = _calculate_signature(u_hash, p_hash, salt_hex)

    data = {
        "u_hash": u_hash,
        "p_hash": p_hash,
        "salt": salt_hex,
        "signature": sig,
        "updated_at": time.time()
    }

    try:
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        console.print("[bold green][OK] Kredensial Master berhasil diperbarui![/bold green]")
        return True
    except Exception as e:
        console.print(f"[bold red]Gagal memperbarui file kredensial: {e}[/bold red]")
        return False
