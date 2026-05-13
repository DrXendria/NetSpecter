#!/usr/bin/env python3
"""
Alert İzleme Modülü - Düzeltilmiş versiyon
Suricata eve.json'ı güvenilir biçimde tail eder
"""

import json
import os
import time
import logging
import re
from collections import defaultdict
from config import CONFIG

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Saldırı imza tablosu
# Her entry: keywords (imza/kategori içinde aranır), action, block_duration
# -----------------------------------------------------------------------
SIGNATURES = {
    'brute_force_ssh': {
        'keywords': ['SSH Scan', 'SSH Brute', 'Potential SSH',
                     'ssh login', 'ET SCAN.*ssh', 'invalid user',
                     'invalid banner', 'banner mismatch', 'ssh.*fail',
                     'ssh.*error', 'ssh.*invalid', 'ssh client'],
        'categories': [],
        'ports': [22],
        'action': 'block',
        'block_duration': 7200,
        'threshold': {'max': 3, 'window': 60},  # 60s içinde 3 alert
    },
    'brute_force_ftp': {
        'keywords': ['FTP Brute', 'ftp brute', 'FTP login', 'ftp.*fail',
                     'ftp.*error', 'invalid password', 'invalid user',
                     'anonymous ftp'],
        'categories': [],
        'ports': [21],
        'action': 'block',
        'block_duration': 7200,
        'threshold': {'max': 3, 'window': 60},
    },
    'brute_force_http': {
        'keywords': ['HTTP Brute', 'Web Brute', 'credential stuffing',
                     'password spray', 'hydra'],
        'categories': [],
        'ports': [80, 443, 8080, 8443],
        'action': 'block',
        'block_duration': 3600,
        'threshold': {'max': 5, 'window': 60},
    },
    'dos_attack': {
        'keywords': ['ET DOS', 'DoS', 'DDoS', 'flood', 'Flood',
                     'SYN flood', 'UDP flood', 'ICMP flood', 'HTTP flood',
                     'Attempted Denial of Service', 'Denial of Service'],
        'categories': ['Denial of Service', 'Attempted Denial of Service'],
        'action': 'block',
        'block_duration': 86400,
        'threshold': None,
    },
    'exploit': {
        'keywords': ['ET EXPLOIT', 'exploit', 'Exploit', 'shellcode',
                     'buffer overflow', 'Remote Code Execution', 'RCE',
                     'CVE-', 'Command Injection', 'SQL Injection',
                     'Path Traversal', 'Directory Traversal',
                     'LFI', 'RFI', 'SSRF', 'XXE'],
        'categories': ['Exploit', 'Web Attack', 'Attempted User Privilege Gain',
                       'Attempted Administrator Privilege Gain'],
        'action': 'block',
        'block_duration': 86400,
        'threshold': None,
    },
    'malware': {
        'keywords': ['ET MALWARE', 'ET TROJAN', 'malware', 'Malware',
                     'trojan', 'Trojan', 'botnet', 'Botnet',
                     'C2', 'Command and Control', 'backdoor', 'ransomware',
                     'rootkit', 'dropper', 'downloader'],
        'categories': ['Malware', 'A Network Trojan was detected'],
        'action': 'block',
        'block_duration': 604800,   # 7 gün
        'permanent': True,
        'threshold': None,
    },
    'web_attack': {
        'keywords': ['ET WEB_SERVER', 'ET WEB_SPECIFIC_APPS', 'Web Attack',
                     'XSS', 'CSRF', 'web shell', 'webshell',
                     'ET SCAN Rapid', 'Scanner', 'GPL WEB_SERVER', 'GPL SQL_INJECTION',
                     'Nikto', 'nikto', 'dirb', 'gobuster', 'wfuzz', 'dirbuster',
                     'sqlmap', 'ffuf', 'feroxbuster', 'wpscan', 'joomscan',
                     'zap', 'burp', 'acunetix', 'nessus', 'openvas', 'arachni'],
        'categories': ['Web Attack', 'Potentially Bad Traffic'],
        'action': 'block',
        'block_duration': 3600,
        'threshold': None,
    },
    'nmap_scan': {
        'keywords': ['ET SCAN', 'nmap', 'NMAP', 'portscan', 'port scan',
                     'Nmap Scripting', 'OS Detection', 'SYN Stealth',
                     'NULL Scan', 'XMAS', 'FIN Scan', 'ACK Scan',
                     'UDP Scan', 'Masscan', 'masscan', 'zmap'],
        'categories': ['Detection of a Network Scan', 'Network Scan'],
        'action': 'block',
        'block_duration': 3600,
        'threshold': None,   # Her tespitten sonra engelle
    },
    'info_leak': {
        'keywords': ['ET INFO', 'ET HUNTING','ET POLICY', 'Information Leak', 'reconnaissance'],
        'categories': ['Attempted Information Leak'],
        'action': 'log',
        'threshold': None,
    },
}


class AlertMonitor:

    def __init__(self, blocker):
        self.blocker = blocker
        # {ip: {sig_name: [timestamp, ...]}}
        self._alert_times = defaultdict(lambda: defaultdict(list))

    # ------------------------------------------------------------------ #
    #  Ana döngü: eve.json'ı güvenilir biçimde tail et                   #
    # ------------------------------------------------------------------ #

    def watch_eve_log(self, path: str):
        logger.info(f"Eve.json bekleniyor: {path}")

        # Dosya oluşana kadar bekle
        for _ in range(60):
            if os.path.exists(path):
                break
            time.sleep(2)
        else:
            logger.error("Eve.json 120 saniyede oluşmadı, Suricata çalışıyor mu?")
            return

        logger.info("Eve.json bulundu, izleme başlıyor...")

        # Dosyanın sonuna atla (önceki kayıtları atla)
        with open(path, 'r', errors='replace') as f:
            f.seek(0, 2)
            pos = f.tell()

        while True:
            try:
                # Dosya silinip yeniden oluşturulduysa (logrotate)
                if not os.path.exists(path):
                    logger.warning("Eve.json kayboldu, bekleniyor...")
                    time.sleep(3)
                    pos = 0
                    continue

                with open(path, 'r', errors='replace') as f:
                    # Dosya küçüldüyse (rotate) başa dön
                    f.seek(0, 2)
                    size = f.tell()
                    if size < pos:
                        logger.info("Eve.json döndü, baştan okuyorum.")
                        pos = 0

                    f.seek(pos)
                    lines = f.readlines()
                    pos = f.tell()

                for line in lines:
                    line = line.strip()
                    if line:
                        self._process(line)

                time.sleep(0.3)

            except Exception as e:
                logger.error(f"Eve.json okuma hatası: {e}")
                time.sleep(2)

    # ------------------------------------------------------------------ #
    #  Event işleme                                                       #
    # ------------------------------------------------------------------ #

    def _process(self, line: str):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            return

        etype = ev.get('event_type', '')

        if etype == 'alert':
            self._handle_alert(ev)
        elif etype == 'anomaly':
            self._handle_anomaly(ev)

    def _handle_alert(self, ev: dict):
        alert     = ev.get('alert', {})
        src_ip    = ev.get('src_ip', '')
        dest_port = ev.get('dest_port', 0)
        signature = alert.get('signature', '')
        category  = alert.get('category', '')
        severity  = alert.get('severity', 3)

        if not src_ip:
            return

        noisy_keywords = ['Python SimpleHTTP ServerBanner', 'Kali Linux hostname in DHCP', 'Telegram API Domain', 'Spotify']
        if any(noise.lower() in signature.lower() for noise in noisy_keywords):
            return

        sig_name = self._classify(signature, category, dest_port)
        self.blocker.increment_alert(sig_name)

        logger.info(
            f"[ALERT] {src_ip} → port {dest_port} | "
            f"{sig_name} | sev={severity} | {signature[:60]}"
        )
        
        # MySQL Veritabanına kaydet
        try:
            from database import save_alert
            save_alert(src_ip, dest_port, sig_name, severity, signature, category)
        except Exception as e:
            logger.error(f"Veritabanına alert kaydedilemedi: {e}")

        sig_def = SIGNATURES.get(sig_name, {})
        action  = sig_def.get('action', 'log')

        # Severity 1-2 veya action=block ise engelle
        if action == 'block' or severity <= 2:
            # Threshold kontrolü
            if not self._threshold_ok(src_ip, sig_name, sig_def):
                return

            self.blocker.block_ip(
                src_ip,
                reason   = f"{sig_name} | {signature[:80]}",
                duration = sig_def.get('block_duration', CONFIG['blocking']['block_duration']),
                permanent= sig_def.get('permanent', False),
            )

    def _handle_anomaly(self, ev: dict):
        src_ip = ev.get('src_ip', '')
        atype  = ev.get('anomaly', {}).get('type', '')
        if src_ip and atype:
            logger.info(f"[ANOMALİ] {src_ip} → {atype}")
            if atype in ('applayer', 'decode', 'stream'):
                self.blocker.block_ip(src_ip, f"Protokol anomalisi: {atype}", duration=1800)

    # ------------------------------------------------------------------ #
    #  Yardımcı fonksiyonlar                                              #
    # ------------------------------------------------------------------ #

    def _classify(self, signature: str, category: str, dest_port: int) -> str:
        for name, sdef in SIGNATURES.items():
            # Anahtar kelime eşleşmesi (regex destekli)
            for kw in sdef.get('keywords', []):
                try:
                    if re.search(kw, signature, re.IGNORECASE):
                        return name
                except re.error:
                    if kw.lower() in signature.lower():
                        return name
            # Kategori eşleşmesi (regex destekli)
            for cat in sdef.get('categories', []):
                try:
                    if re.search(cat, category, re.IGNORECASE):
                        return name
                except re.error:
                    if cat.lower() in category.lower():
                        return name
            # Port eşleşmesi (varsa)
            if dest_port and dest_port in sdef.get('ports', []):
                if any((kw.lower() in signature.lower() or kw.lower() in category.lower())
                       for kw in sdef.get('keywords', [])):
                    return name

        # Eğer hala bulunamadıysa port numarasına göre varsayılan bir kategori atayabiliriz
        if dest_port:
            if dest_port == 22:
                return 'brute_force_ssh'
            if dest_port == 21:
                return 'brute_force_ftp'
            if dest_port in (80, 443, 8080, 8443):
                # Web portlarına gelen ve unknown kalan uyarıları web saldırısı olarak işaretle
                return 'web_attack'

        return 'unknown'

    def _threshold_ok(self, ip: str, sig_name: str, sig_def: dict) -> bool:
        """
        Threshold None ise → her alert'te engelle (True döner).
        Threshold tanımlıysa → zaman penceresinde yeterli alert birikince True döner.
        """
        th = sig_def.get('threshold')
        if th is None:
            return True

        now   = time.time()
        win   = th['window']
        maxn  = th['max']
        times = self._alert_times[ip][sig_name]

        # Eski kayıtları temizle
        times = [t for t in times if now - t < win]
        times.append(now)
        self._alert_times[ip][sig_name] = times

        if len(times) >= maxn:
            logger.info(f"Threshold aşıldı: {ip} {sig_name} ({len(times)}/{maxn})")
            return True
        return False
