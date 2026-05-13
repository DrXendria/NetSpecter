#!/usr/bin/env python3
"""
NetSpecter — Telegram Bildirim Botu
Eve.json'u izler, kritik olaylarda Telegram'a mesaj gönderir.

Kurulum:
  pip3 install requests --break-system-packages
  nano /opt/netspecter/telegram_bot.py  (BOT_TOKEN ve CHAT_ID girin)
  sudo python3 /opt/netspecter/telegram_bot.py

Bot Token almak için: Telegram'da @BotFather → /newbot
Chat ID almak için:   @userinfobot'a mesaj at
"""

import os
import subprocess
import sys
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

import requests
from pathlib import Path


def load_env(env_path: str = None):
    """
    .env dosyasını yükler. Önce belirtilen yola, sonra şu sırayla bakar:
      1. /opt/netspecter/.env
      2. Script'in yanındaki .env
      3. Çalışma dizinindeki .env
    """
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates += [
        Path('/opt/netspecter/.env'),
        Path(__file__).parent / '.env',
        Path('.env'),
    ]
    for path in candidates:
        if path.exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    key, _, val = line.partition('=')
                    os.environ.setdefault(key.strip(), val.strip())
            print(f'[BOT] .env yüklendi: {path}')
            return str(path)
    return None


# .env dosyasını yükle
load_env()

# ── AYARLAR (.env'den okunur) ───────────────────────────────────────────
BOT_TOKEN        = os.getenv('TELEGRAM_BOT_TOKEN', '')
CHAT_ID          = os.getenv('TELEGRAM_CHAT_ID', '')
DDOS_TIME_WINDOW = int(os.getenv('DDOS_TIME_WINDOW', '60'))
DDOS_MIN_IPS     = int(os.getenv('DDOS_MIN_IPS', '10'))
NOTIFY_COOLDOWN  = int(os.getenv('NOTIFY_COOLDOWN', '300'))
EVE_PATH         = '/var/log/suricata/eve.json'
# ───────────────────────────────────────────────────────────────────────

ATTACK_LABELS = {
    'nmap_scan':        'Port Tarama',
    'brute_force_ssh':  'SSH Brute Force',
    'brute_force_ftp':  'FTP Brute Force',
    'brute_force_http': 'HTTP Brute Force',
    'dos_attack':       'DoS Saldırısı',
    'exploit':          'Exploit',
    'malware':          'Malware / Trojan',
    'web_attack':       'Web Saldırısı',
    'info_leak':        'Bilgi Sızıntısı',
    'unknown':          'Bilinmeyen',
}

ATTACK_EMOJIS = {
    'nmap_scan':        '🔍',
    'brute_force_ssh':  '🔑',
    'brute_force_ftp':  '🔑',
    'brute_force_http': '🔑',
    'dos_attack':       '💥',
    'exploit':          '☠️',
    'malware':          '🦠',
    'web_attack':       '🕷️',
    'info_leak':        '📡',
    'unknown':          '⚠️',
}


def classify(signature: str, category: str, dest_port: int = 0) -> str:
    sig_l = signature.lower()
    cat_l = category.lower()
    mapping = {
        'brute_force_ssh':  ['ssh scan', 'ssh brute', 'potential ssh', 'ssh login', 'et scan.*ssh', 'invalid user', 'invalid banner', 'banner mismatch', 'ssh.*fail', 'ssh.*error', 'ssh.*invalid', 'ssh client'],
        'brute_force_ftp':  ['ftp brute', 'ftp login', 'ftp.*fail', 'ftp.*error', 'invalid password', 'invalid user', 'anonymous ftp'],
        'brute_force_http': ['http brute', 'web brute', 'credential stuffing', 'password spray', 'nikto', 'dirb', 'gobuster', 'wfuzz', 'dirbuster', 'sqlmap', 'hydra', 'ffuf', 'feroxbuster', 'wpscan', 'joomscan', 'zap', 'burp', 'acunetix', 'nessus', 'openvas', 'arachni'],
        'dos_attack':       ['et dos', 'dos', 'ddos', 'flood', 'denial of service', 'attempted denial of service'],
        'exploit':          ['et exploit', 'exploit', 'shellcode', 'buffer overflow', 'remote code execution', 'rce', 'cve-', 'command injection', 'sql injection', 'path traversal', 'directory traversal', 'lfi', 'rfi', 'ssrf', 'xxe'],
        'malware':          ['et malware', 'et trojan', 'malware', 'trojan', 'botnet', 'c2', 'command and control', 'backdoor', 'ransomware', 'rootkit', 'dropper', 'downloader'],
        'web_attack':       ['et web_server', 'et web_specific', 'web attack', 'xss', 'csrf', 'web shell', 'webshell', 'scanner', 'applayer detect', 'http host header', 'gpl web_server', 'gpl sql_injection'],
        'nmap_scan':        ['et scan', 'nmap', 'portscan', 'port scan', 'os detection', 'syn stealth', 'null scan', 'xmas', 'fin scan', 'ack scan', 'udp scan', 'masscan', 'zmap'],
        'info_leak':        ['et info','et hunting','et policy', 'information leak', 'reconnaissance'],
    }
    import re
    for attack, keywords in mapping.items():
        for kw in keywords:
            try:
                if re.search(kw, sig_l) or re.search(kw, cat_l):
                    return attack
            except re.error:
                if kw in sig_l or kw in cat_l:
                    return attack

    if dest_port:
        if dest_port == 22: return 'brute_force_ssh'
        if dest_port == 21: return 'brute_force_ftp'
        if dest_port in (80, 443, 8080, 8443): return 'web_attack'

    return 'unknown'


def send_telegram(text: str) -> bool:
    """Telegram mesajı gönder. Başarıysa True döner."""
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    try:
        r = requests.post(url, json={
            'chat_id':    CHAT_ID,
            'text':       text,
            'parse_mode': 'HTML',
        }, timeout=10)
        return r.status_code == 200
    except Exception as e:
        print(f'[Telegram HATA] {e}')
        return False


def fmt_time() -> str:
    return datetime.now().strftime('%d.%m.%Y %H:%M:%S')


def build_alert_msg(ip, attack_type, severity, dest_port, signature, violation_count=1) -> str:
    emoji = ATTACK_EMOJIS.get(attack_type, '⚠️')
    label = ATTACK_LABELS.get(attack_type, attack_type)
    sev_str = '🔴 KRİTİK' if severity == 1 else '🟠 YÜKSEK'
    return (
        f'{emoji} <b>NetSpecter Uyarısı</b>\n'
        f'━━━━━━━━━━━━━━━━━━━━\n'
        f'🕐 <b>Zaman:</b> {fmt_time()}\n'
        f'🌐 <b>Kaynak IP:</b> <code>{ip}</code>\n'
        f'⚡ <b>Saldırı Tipi:</b> {label}\n'
        f'🎯 <b>Hedef Port:</b> {dest_port}\n'
        f'📊 <b>Önem:</b> {sev_str} (sev={severity})\n'
        f'🔁 <b>İhlal Sayısı:</b> {violation_count}\n'
        f'📝 <b>İmza:</b> <code>{signature[:100]}</code>'
    )


def build_ddos_msg(attack_type, ip_count, sample_ips, time_window) -> str:
    emoji = '🚨'
    label = ATTACK_LABELS.get(attack_type, attack_type)
    sample = '\n'.join(f'  • <code>{ip}</code>' for ip in list(sample_ips)[:5])
    return (
        f'{emoji} <b>OLASI DDoS SALDIRISI!</b>\n'
        f'━━━━━━━━━━━━━━━━━━━━\n'
        f'🕐 <b>Zaman:</b> {fmt_time()}\n'
        f'⚡ <b>Saldırı Tipi:</b> {label}\n'
        f'👥 <b>Farklı IP Sayısı:</b> {ip_count} ({time_window}sn içinde)\n'
        f'🔍 <b>Örnek IP\'ler:</b>\n{sample}\n'
        f'━━━━━━━━━━━━━━━━━━━━\n'
        f'⚠️ <b>Birden fazla kaynaktan koordineli saldırı tespit edildi!</b>'
    )


class TelegramNotifier:
    def __init__(self):
        # Cooldown: {ip} → last_notify_timestamp
        self.cooldown: dict[str, float] = {}
        # DDoS tracker: {attack_type} → deque of (timestamp, ip)
        self.ddos_tracker: dict[str, deque] = defaultdict(lambda: deque())
        # DDoS bildirimi cooldown
        self.ddos_notified: dict[str, float] = {}

    def _in_cooldown(self, ip: str) -> bool:
        last = self.cooldown.get(ip, 0)
        return (time.time() - last) < NOTIFY_COOLDOWN

    def _set_cooldown(self, ip: str):
        self.cooldown[ip] = time.time()

    def process_alert(self, ev: dict):
        alert      = ev.get('alert', {})
        src_ip     = ev.get('src_ip', '')
        dest_port  = ev.get('dest_port', 0)
        signature  = alert.get('signature', '')
        category   = alert.get('category', '')
        severity   = alert.get('severity', 4)

        noisy_keywords = ['Python SimpleHTTP ServerBanner', 'Kali Linux hostname in DHCP', 'Telegram API Domain', 'Spotify']
        if any(noise.lower() in signature.lower() for noise in noisy_keywords):
            return

        attack_type = classify(signature, category, dest_port)

        # ── DDoS tespiti ────────────────────────────────────────────────
        now = time.time()
        tracker = self.ddos_tracker[attack_type]
        tracker.append((now, src_ip))

        # Zaman penceresini temizle
        while tracker and (now - tracker[0][0]) > DDOS_TIME_WINDOW:
            tracker.popleft()

        unique_ips = {ip for _, ip in tracker}

        if len(unique_ips) >= DDOS_MIN_IPS:
            last_ddos = self.ddos_notified.get(attack_type, 0)
            if (now - last_ddos) > NOTIFY_COOLDOWN:
                msg = build_ddos_msg(attack_type, len(unique_ips), unique_ips, DDOS_TIME_WINDOW)
                if send_telegram(msg):
                    self.ddos_notified[attack_type] = now
                    print(f'[BOT] DDoS bildirimi gönderildi: {attack_type} ({len(unique_ips)} IP)')

        # ── Yüksek severity bildirimi ────────────────────────────────────
        if severity <= 2:
            if self._in_cooldown(src_ip):
                return

            # İhlal sayısını state'den oku
            violation_count = self._get_violation_count(src_ip)

            msg = build_alert_msg(src_ip, attack_type, severity, dest_port, signature, violation_count)
            if send_telegram(msg):
                self._set_cooldown(src_ip)
                print(f'[BOT] Yüksek severity bildirimi: {src_ip} | {attack_type} | sev={severity}')

    def _get_violation_count(self, ip: str) -> int:
        try:
            from database import get_violation_count
            return get_violation_count(ip) or 1
        except Exception as e:
            print(f"[BOT HATA] get_violation_count hatası: {e}")
            return 1


def watch_eve(notifier: TelegramNotifier):
    """Eve.json'u tail -f gibi izle"""
    print(f'[BOT] Eve.json bekleniyor: {EVE_PATH}')
    while not os.path.exists(EVE_PATH):
        time.sleep(2)

    print(f'[BOT] İzleme başladı.')
    pos = 0
    with open(EVE_PATH, 'r', errors='replace') as f:
        f.seek(0, 2)
        pos = f.tell()

    while True:
        try:
            if not os.path.exists(EVE_PATH):
                time.sleep(3)
                continue

            with open(EVE_PATH, 'r', errors='replace') as f:
                f.seek(0, 2)
                size = f.tell()
                if size < pos:
                    pos = 0
                f.seek(pos)
                lines = f.readlines()
                pos = f.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get('event_type') == 'alert':
                    notifier.process_alert(ev)

            time.sleep(0.5)

        except Exception as e:
            print(f'[BOT HATA] {e}')
            time.sleep(3)


def check_config():
    errors = []
    if BOT_TOKEN == 'BURAYA_BOT_TOKEN':
        errors.append('BOT_TOKEN girilmemiş!')
    if CHAT_ID == 'BURAYA_CHAT_ID':
        errors.append('CHAT_ID girilmemiş!')
    return errors


def test_connection():
    """Başlangıçta test mesajı gönder"""
    msg = (
        '✅ <b>NetSpecter Bot Aktif</b>\n'
        f'🕐 {fmt_time()}\n'
        f'🛡️ IDS/IPS sistemi izleniyor.\n\n'
        f'📢 Bildirim koşulları:\n'
        f'  • DDoS: {DDOS_TIME_WINDOW}sn içinde {DDOS_MIN_IPS}+ farklı IP\n'
        f'  • Yüksek severity alertler (sev=1 veya sev=2)'
    )
    return send_telegram(msg)


if __name__ == '__main__':
    # Eski process'leri temizle
    import signal
    current_pid = os.getpid()
    result = subprocess.run(['pgrep', '-f', 'telegram_bot.py'], capture_output=True, text=True)
    for pid_str in result.stdout.strip().splitlines():
        pid = int(pid_str)
        if pid != current_pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    time.sleep(1)

    print("""
╔══════════════════════════════════════════╗
║    NetSpecter — Telegram Bildirim Botu   ║
╚══════════════════════════════════════════╝
""")

    # Yapılandırma kontrolü
    errors = check_config()
    if errors:
        print('HATA — Yapılandırma eksik:')
        for e in errors:
            print(f'  ✗ {e}')
        print('\ntelegram_bot.py dosyasını açıp BOT_TOKEN ve CHAT_ID değerlerini girin.')
        print('\nBot Token için: Telegram → @BotFather → /newbot')
        print('Chat ID için:   Telegram → @userinfobot')
        sys.exit(1)

    # Bağlantı testi
    print('[BOT] Telegram bağlantısı test ediliyor...')
    if test_connection():
        print('[BOT] ✓ Telegram bağlantısı başarılı, test mesajı gönderildi.')
    else:
        print('[BOT] ✗ Telegram bağlantısı başarısız! Token ve Chat ID\'yi kontrol edin.')
        sys.exit(1)

    # Eve.json izleyiciyi başlat
    notifier = TelegramNotifier()
    watch_eve(notifier)
