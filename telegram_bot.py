#!/usr/bin/env python3
"""
NetSpecter — Telegram Bildirim Botu
Eve.json'u izler, kritik olaylarda Telegram'a mesaj gönderir.
"""

import os
import subprocess
import sys
import json
import time
import signal
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

import requests

try:
    from database import save_ddos_event, get_violation_count
    DB_ENABLED = True
except ImportError:
    DB_ENABLED = False


def load_env(env_path: str = None):
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


load_env()

BOT_TOKEN        = os.getenv('TELEGRAM_BOT_TOKEN', '')
CHAT_ID          = os.getenv('TELEGRAM_CHAT_ID', '')
DDOS_TIME_WINDOW = int(os.getenv('DDOS_TIME_WINDOW', '60'))
DDOS_MIN_IPS     = int(os.getenv('DDOS_MIN_IPS', '10'))
NOTIFY_COOLDOWN  = int(os.getenv('NOTIFY_COOLDOWN', '300'))
EVE_PATH         = '/var/log/suricata/eve.json'

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


def classify(signature: str, category: str) -> str:
    sig_l = signature.lower()
    cat_l = category.lower()
    mapping = {
        'nmap_scan':        ['nmap', 'et scan', 'port scan', 'portscan'],
        'brute_force_ssh':  ['ssh brute', 'ssh scan', 'ssh login'],
        'brute_force_ftp':  ['ftp brute', 'ftp login'],
        'brute_force_http': ['http brute', 'nikto', 'dirb', 'gobuster', 'sqlmap'],
        'dos_attack':       ['et dos', 'flood', 'denial of service'],
        'exploit':          ['et exploit', 'exploit', 'shellcode', 'cve-', 'rce'],
        'malware':          ['et malware', 'et trojan', 'malware', 'trojan', 'botnet'],
        'web_attack':       ['et web_server', 'et web_specific', 'xss', 'sql injection'],
        'info_leak':        ['et info', 'information leak'],
    }
    for attack, keywords in mapping.items():
        if any(k in sig_l or k in cat_l for k in keywords):
            return attack
    if 'scan' in cat_l: return 'nmap_scan'
    if 'dos'  in cat_l: return 'dos_attack'
    return 'unknown'


def send_telegram(text: str) -> bool:
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
    emoji   = ATTACK_EMOJIS.get(attack_type, '⚠️')
    label   = ATTACK_LABELS.get(attack_type, attack_type)
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
    label  = ATTACK_LABELS.get(attack_type, attack_type)
    sample = '\n'.join(f'  • <code>{ip}</code>' for ip in list(sample_ips)[:5])
    return (
        f'🚨 <b>OLASI DDoS SALDIRISI!</b>\n'
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
        self.cooldown:      dict[str, float] = {}
        self.ddos_tracker:  dict[str, deque] = defaultdict(lambda: deque())
        self.ddos_notified: dict[str, float] = {}

    def _in_cooldown(self, ip: str) -> bool:
        return (time.time() - self.cooldown.get(ip, 0)) < NOTIFY_COOLDOWN

    def _set_cooldown(self, ip: str):
        self.cooldown[ip] = time.time()

    def _get_violation_count(self, ip: str) -> int:
        if DB_ENABLED:
            try:
                return get_violation_count(ip)
            except Exception:
                pass
        try:
            with open('/var/log/netspecter/state.json') as f:
                state = json.load(f)
            return state.get('violation_counts', {}).get(ip, 1)
        except Exception:
            return 1

    def process_alert(self, ev: dict):
        alert      = ev.get('alert', {})
        src_ip     = ev.get('src_ip', '')
        dest_port  = ev.get('dest_port', 0)
        signature  = alert.get('signature', '')
        category   = alert.get('category', '')
        severity   = alert.get('severity', 4)

        attack_type = classify(signature, category)
        now         = time.time()

        # ── DDoS tespiti ────────────────────────────────────────────────
        tracker = self.ddos_tracker[attack_type]
        tracker.append((now, src_ip))
        while tracker and (now - tracker[0][0]) > DDOS_TIME_WINDOW:
            tracker.popleft()

        unique_ips = {ip for _, ip in tracker}
        if len(unique_ips) >= DDOS_MIN_IPS:
            last_ddos = self.ddos_notified.get(attack_type, 0)
            if (now - last_ddos) > NOTIFY_COOLDOWN:
                msg = build_ddos_msg(attack_type, len(unique_ips), unique_ips, DDOS_TIME_WINDOW)
                if send_telegram(msg):
                    self.ddos_notified[attack_type] = now
                    print(f'[BOT] DDoS bildirimi: {attack_type} ({len(unique_ips)} IP)')
                    if DB_ENABLED:
                        try:
                            save_ddos_event(attack_type, len(unique_ips), DDOS_TIME_WINDOW, unique_ips)
                        except Exception as e:
                            print(f'[BOT] DB kayıt hatası: {e}')

        # ── Tüm alertler için bildirim ───────────────────────────────────
        # Zararsız imzaları filtrele
        HARMLESS_SIGNATURES = [
            'spotify', 'telegram api', 'simplehttps', 'simplehttps',
            'python simplehttp', 'p2p client',
        ]
        sig_lower = signature.lower()
        if any(h in sig_lower for h in HARMLESS_SIGNATURES):
            return

        # info_leak bildirim gönderme (Spotify gibi zararsız trafik)
        if attack_type == 'info_leak':
            return

        if self._in_cooldown(src_ip):
            return

        violation_count = self._get_violation_count(src_ip)
        sev_str = '🔴 KRİTİK' if severity == 1 else ('🟠 YÜKSEK' if severity == 2 else '🟡 ORTA')
        msg = build_alert_msg(src_ip, attack_type, severity, dest_port, signature, violation_count)
        if send_telegram(msg):
            self._set_cooldown(src_ip)
            print(f'[BOT] Bildirim: {src_ip} | {attack_type} | sev={severity}')


def watch_eve(notifier: TelegramNotifier):
    print(f'[BOT] Eve.json bekleniyor: {EVE_PATH}')
    while not os.path.exists(EVE_PATH):
        time.sleep(2)

    print('[BOT] İzleme başladı.')
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
    if not BOT_TOKEN or BOT_TOKEN == 'BURAYA_BOT_TOKEN':
        errors.append('BOT_TOKEN girilmemiş!')
    if not CHAT_ID or CHAT_ID == 'BURAYA_CHAT_ID':
        errors.append('CHAT_ID girilmemiş!')
    return errors


def test_connection():
    msg = (
        '✅ <b>NetSpecter Bot Aktif</b>\n'
        f'🕐 {fmt_time()}\n'
        f'🛡️ IDS/IPS sistemi izleniyor.\n\n'
        f'📢 Tüm alertler için bildirim aktif.\n'
        f'🚨 DDoS: {DDOS_TIME_WINDOW}sn içinde {DDOS_MIN_IPS}+ farklı IP'
    )
    return send_telegram(msg)


if __name__ == '__main__':
    # Eski process'leri temizle
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

    errors = check_config()
    if errors:
        print('HATA — Yapılandırma eksik:')
        for e in errors:
            print(f'  ✗ {e}')
        sys.exit(1)

    print('[BOT] Telegram bağlantısı test ediliyor...')
    if test_connection():
        print('[BOT] ✓ Bağlantı başarılı, test mesajı gönderildi.')
    else:
        print('[BOT] ✗ Bağlantı başarısız!')
        sys.exit(1)

    notifier = TelegramNotifier()
    watch_eve(notifier)
