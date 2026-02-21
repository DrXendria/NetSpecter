#!/usr/bin/env python3
"""
NetSpecter — CLI Başlatıcı
Kullanım: sudo netspecter
"""

import os
import sys
import subprocess
import time
import json
import re
from datetime import datetime

# ── Renkler ────────────────────────────────────────────────────────────
R  = '\033[0;31m'    # Kırmızı
G  = '\033[0;32m'    # Yeşil
Y  = '\033[1;33m'    # Sarı
B  = '\033[1;34m'    # Mavi
M  = '\033[0;35m'    # Mor
C  = '\033[0;36m'    # Cyan
W  = '\033[1;37m'    # Beyaz parlak
DIM= '\033[2m'       # Soluk
NC = '\033[0m'       # Reset
BOLD='\033[1m'

# Saldırı tipi renkleri
ATTACK_COLORS = {
    'nmap_scan':        Y,
    'brute_force_ssh':  R,
    'brute_force_ftp':  R,
    'brute_force_http': R,
    'dos_attack':       M,
    'exploit':          R,
    'malware':          R + BOLD,
    'web_attack':       Y,
    'info_leak':        C,
    'unknown':          DIM,
}

ATTACK_LABELS = {
    'nmap_scan':        'PORT TARAMA',
    'brute_force_ssh':  'SSH BRUTE FORCE',
    'brute_force_ftp':  'FTP BRUTE FORCE',
    'brute_force_http': 'HTTP BRUTE FORCE',
    'dos_attack':       'DoS SALDIRISI',
    'exploit':          'EXPLOIT',
    'malware':          'MALWARE',
    'web_attack':       'WEB SALDIRISI',
    'info_leak':        'BİLGİ SIZINTISI',
    'unknown':          'BİLİNMEYEN',
}


def clear():
    os.system('clear')


def banner():
    print(f"""
{B}╔══════════════════════════════════════════════════════╗
║         {W}NetSpecter IDS/IPS  —  v2.0{B}                  ║
║         {DIM}Raspberry Pi Saldırı Tespit Sistemi{B}           ║
╚══════════════════════════════════════════════════════╝{NC}
""")


def divider(char='─', color=DIM):
    print(f"{color}{char * 56}{NC}")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def is_running():
    r = run(['systemctl', 'is-active', 'netspecter'])
    return r.stdout.strip() == 'active'


def start_service():
    """Servisi başlat veya restart et"""
    if is_running():
        print(f"  {Y}↻{NC}  Servis yeniden başlatılıyor...")
        run(['systemctl', 'restart', 'netspecter'])
    else:
        print(f"  {G}▶{NC}  NetSpecter başlatılıyor...")
        run(['systemctl', 'start', 'netspecter'])

    # Servisin ayağa kalkmasını bekle
    for i in range(10):
        time.sleep(1)
        if is_running():
            print(f"  {G}✓{NC}  Servis aktif.\n")
            return True
        print(f"  {DIM}  Bekleniyor... ({i+1}s){NC}", end='\r')

    print(f"\n  {R}✗{NC}  Servis başlatılamadı!")
    print(f"  {DIM}Detay için: journalctl -u netspecter -n 20{NC}")
    return False


def get_stats():
    """State dosyasından istatistik oku"""
    try:
        with open('/var/log/netspecter/state.json') as f:
            state = json.load(f)
        blocked = state.get('blocked_ips', {})
        return {
            'blocked_count':   len(blocked),
            'permanent_count': sum(1 for i in blocked.values() if i.get('permanent')),
            'top_violations':  sorted(
                state.get('violation_counts', {}).items(),
                key=lambda x: -x[1]
            )[:3],
        }
    except Exception:
        return {'blocked_count': 0, 'permanent_count': 0, 'top_violations': []}


def status_bar():
    """Üst durum çubuğunu yazdır"""
    stats  = get_stats()
    now    = datetime.now().strftime('%H:%M:%S')
    status = f"{G}● AKTİF{NC}" if is_running() else f"{R}● DURDURULDU{NC}"

    print(f"  {status}    "
          f"{W}Engelli:{NC} {R}{stats['blocked_count']}{NC}    "
          f"{W}Kalıcı:{NC} {R}{stats['permanent_count']}{NC}    "
          f"{DIM}{now}{NC}")
    divider()


def format_log_line(line: str) -> str:
    """
    journalctl çıktısından anlamlı satırları güzel formata çevir.
    None dönerse satırı atla.
    """
    # journalctl prefix'ini temizle (tarih, hostname, servis adı)
    # Örnek: "Şub 20 23:16:57 raspberrypi python3[3084]: [INFO] ..."
    match = re.search(r'python3\[\d+\]: (.+)', line)
    if match:
        content = match.group(1).strip()
    else:
        content = line.strip()

    # Boş veya sadece log level içeren satırları atla
    skip_patterns = [
        'DEBUG', 'Traceback', 'File "/', r'line \d+',
        'Starting', 'Started', 'Stopping', 'Stopped',
        'daemon:', 'systemd',
    ]
    if any(p in content for p in skip_patterns):
        return None

    # ── ENGELLEME ──────────────────────────────────────────────────────
    if '[ENGELLENDİ]' in content:
        # Format: [ENGELLENDİ] IP | sebep | Süre: X | İhlal #N
        parts = content.replace('[ENGELLENDİ]', '').strip().split('|')
        ip     = parts[0].strip() if len(parts) > 0 else '?'
        reason = parts[1].strip() if len(parts) > 1 else ''
        sure   = parts[2].strip() if len(parts) > 2 else ''
        ihlal  = parts[3].strip() if len(parts) > 3 else ''

        # Saldırı tipini bul
        attack_key = reason.split()[0] if reason else 'unknown'
        color = ATTACK_COLORS.get(attack_key, R)
        label = ATTACK_LABELS.get(attack_key, 'SALDIRI')

        now = datetime.now().strftime('%H:%M:%S')
        return (
            f"\n{R}┌─ 🚫 ENGELLEME {'─'*38}┐{NC}\n"
            f"{R}│{NC}  {W}IP    :{NC} {R}{BOLD}{ip:<20}{NC}\n"
            f"{R}│{NC}  {W}Tip   :{NC} {color}{label}{NC}\n"
            f"{R}│{NC}  {W}Sebep :{NC} {DIM}{reason[:50]}{NC}\n"
            f"{R}│{NC}  {W}Durum :{NC} {sure}  {DIM}{ihlal}{NC}\n"
            f"{R}└{'─'*44}┘{NC}"
        )

    # ── ALERT ──────────────────────────────────────────────────────────
    if '[ALERT]' in content:
        # Format: [ALERT] IP → port X | tip | sev=N | imza
        content_clean = content.replace('[ALERT]', '').strip()
        parts = content_clean.split('|')
        conn   = parts[0].strip() if len(parts) > 0 else ''
        tip    = parts[1].strip() if len(parts) > 1 else ''
        sev    = parts[2].strip() if len(parts) > 2 else ''
        imza   = parts[3].strip() if len(parts) > 3 else ''

        color = ATTACK_COLORS.get(tip, Y)
        label = ATTACK_LABELS.get(tip, tip.upper())
        sev_num = sev.replace('sev=', '')
        sev_color = R if sev_num in ('1', '2') else Y

        now = datetime.now().strftime('%H:%M:%S')
        return (
            f"{Y}│{NC} {DIM}{now}{NC} {W}ALERT{NC}  "
            f"{color}{label:<20}{NC}  "
            f"{W}{conn}{NC}  "
            f"{sev_color}[sev={sev_num}]{NC}"
        )

    # ── ENGEL KALDIRILDI ───────────────────────────────────────────────
    if '[ENGEL KALDIRILDI]' in content:
        ip = content.replace('[ENGEL KALDIRILDI]', '').strip()
        now = datetime.now().strftime('%H:%M:%S')
        return f"{G}│{NC} {DIM}{now}{NC} {G}ENGEL KALDIRILDI{NC}  {W}{ip}{NC}"

    # ── ANOMALİ ────────────────────────────────────────────────────────
    if '[ANOMALİ]' in content:
        now = datetime.now().strftime('%H:%M:%S')
        return f"{M}│{NC} {DIM}{now}{NC} {M}ANOMALİ{NC}  {content.replace('[ANOMALİ]','').strip()}"

    # ── SİSTEM MESAJLARI ───────────────────────────────────────────────
    system_keywords = {
        'başlatılıyor': (G, '▶'),
        'başlatıldı':   (G, '✓'),
        'aktif':        (G, '✓'),
        'hazır':        (G, '✓'),
        'zinciri hazır':(G, '✓'),
        'durduruluyor': (Y, '↻'),
        'kurallar':     (C, '↓'),
        'güncellendi':  (C, '✓'),
        'bekleniyor':   (DIM,'…'),
        'hata':         (R, '✗'),
        'error':        (R, '✗'),
    }
    content_l = content.lower()
    for kw, (color, icon) in system_keywords.items():
        if kw in content_l:
            now = datetime.now().strftime('%H:%M:%S')
            clean = re.sub(r'\[INFO\]|\[WARNING\]|\[ERROR\]', '', content).strip()
            return f"{color}│{NC} {DIM}{now}{NC} {color}{icon}  {clean}{NC}"

    return None


def watch_logs():
    """journalctl çıktısını canlı izle ve güzel formatta göster"""

    print(f"\n{DIM}  Ctrl+C ile log izlemeyi durdurabilirsiniz "
          f"(servis çalışmaya devam eder){NC}\n")
    divider('═', B)
    print(f"  {W}CANLI OLAY AKIŞI{NC}")
    divider('═', B)
    print()

    proc = subprocess.Popen(
        ['journalctl', '-u', 'netspecter', '-f', '-n', '0',
         '--no-pager', '--output=short'],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    try:
        for line in proc.stdout:
            formatted = format_log_line(line)
            if formatted:
                print(formatted)
    except KeyboardInterrupt:
        proc.terminate()
        print(f"\n\n{DIM}  Log izleme durduruldu. "
              f"NetSpecter arka planda çalışmaya devam ediyor.{NC}")
        print(f"  {DIM}Tekrar izlemek için: sudo netspecter{NC}\n")


def start_telegram_bot():
    """Telegram botunu arka planda başlat (zaten çalışıyorsa atla)"""
    bot_path = '/opt/netspecter/telegram_bot.py'
    if not os.path.exists(bot_path):
        return

    # Zaten çalışıyor mu?
    check = subprocess.run(['pgrep', '-f', 'telegram_bot.py'], capture_output=True)
    if check.returncode == 0:
        print(f"  {G}✓{NC}  Telegram botu zaten çalışıyor.")
        return

    # .env var mı?
    if not os.path.exists('/opt/netspecter/.env'):
        print(f"  {DIM}  Telegram botu: .env bulunamadı, atlanıyor.{NC}")
        return

    print(f"  {B}▶{NC}  Telegram botu başlatılıyor (arka plan)...")
    subprocess.Popen(
        ['python3', bot_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    print(f"  {G}✓{NC}  Telegram botu aktif.")


def start_dashboard():
    """Dashboard'u arka planda başlat (zaten çalışıyorsa atla)"""
    # Port 5000 açık mı kontrol et
    check = subprocess.run(
        ['ss', '-tlnp'],
        capture_output=True, text=True
    )
    if ':5000' in check.stdout:
        print(f"  {G}✓{NC}  Dashboard zaten çalışıyor → {C}http://localhost:5000{NC}")
        return

    print(f"  {B}▶{NC}  Dashboard başlatılıyor (arka plan)...")
    subprocess.Popen(
        ['python3', '/opt/netspecter/dashboard.py'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Kısa bekle, sonra kontrol et
    import time as _time; _time.sleep(2)
    check2 = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
    if ':5000' in check2.stdout:
        print(f"  {G}✓{NC}  Dashboard aktif → {C}http://localhost:5000{NC}")
    else:
        print(f"  {DIM}  Dashboard başlatılamadı (flask kurulu mu?){NC}")


def main():
    if os.geteuid() != 0:
        print(f"\n{R}  Root gerekli:{NC}  sudo netspecter\n")
        sys.exit(1)

    clear()
    banner()
    status_bar()
    print()

    # Servisi başlat/restart et
    if not start_service():
        sys.exit(1)

    # Dashboard'u arka planda başlat
    start_dashboard()

    # Telegram botunu arka planda başlat
    start_telegram_bot()
    print()

    # Durum çubuğunu güncelle
    status_bar()

    # Canlı log izleme
    watch_logs()


if __name__ == '__main__':
    main()
