#!/usr/bin/env python3
"""
IP Engelleme Modülü - Düzeltilmiş versiyon
iptables IDS_IPS zincirini güvenli şekilde yönetir
"""

import subprocess
import logging
import time
import json
import os
import ipaddress
from collections import defaultdict
from threading import Lock
from datetime import datetime

from config import CONFIG

logger = logging.getLogger(__name__)


def _run(cmd: list, check=False) -> subprocess.CompletedProcess:
    """Sessiz subprocess çalıştır"""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


class IPBlocker:

    CHAIN = 'IDS_IPS'

    def __init__(self):
        self.blocked_ips   = {}                      # ip → {time, reason, permanent, duration}
        self.violation_cnt = defaultdict(int)        # ip → toplam ihlal sayısı
        self.lock          = Lock()
        self.stats         = {
            'total_blocked': 0,
            'total_alerts':  0,
            'attack_types':  defaultdict(int),
        }
        self.whitelist = set(CONFIG['blocking']['whitelist'])
        self._load_state()

    # ------------------------------------------------------------------ #
    #  iptables zincir kurulumu                                           #
    # ------------------------------------------------------------------ #

    def setup_initial_rules(self):
        """IDS_IPS zincirini sıfırdan güvenli biçimde kur"""
        logger.info("iptables kuralları kuruluyor...")

        # Önce INPUT/FORWARD'dan zincire yönlendirmeleri kaldır (hata olursa sorun yok)
        _run(['iptables', '-D', 'INPUT',   '-j', self.CHAIN])
        _run(['iptables', '-D', 'FORWARD', '-j', self.CHAIN])

        # Zinciri temizle ve sil (varsa)
        _run(['iptables', '-F', self.CHAIN])
        _run(['iptables', '-X', self.CHAIN])

        # Zinciri yeniden oluştur
        r = _run(['iptables', '-N', self.CHAIN])
        if r.returncode != 0:
            logger.error(f"Zincir oluşturulamadı: {r.stderr}")
            return False

        # INPUT ve FORWARD'dan zincire yönlendir
        _run(['iptables', '-I', 'INPUT',   '1', '-j', self.CHAIN])
        _run(['iptables', '-I', 'FORWARD', '1', '-j', self.CHAIN])

        rules = [
            # Loopback'e dokunma
            ['-A', self.CHAIN, '-i', 'lo', '-j', 'RETURN'],

            # Kurulu bağlantılara izin ver
            ['-A', self.CHAIN, '-m', 'state',
             '--state', 'ESTABLISHED,RELATED', '-j', 'RETURN'],

            # SYN flood: burst 50'yi geçen SYN'leri düşür
            ['-A', self.CHAIN, '-p', 'tcp', '--syn',
             '-m', 'limit', '--limit', '20/s', '--limit-burst', '50', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-p', 'tcp', '--syn', '-j', 'DROP'],

            # NULL scan (hiç flag yok)
            ['-A', self.CHAIN, '-p', 'tcp',
             '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'],

            # XMAS scan (tüm flagler set)
            ['-A', self.CHAIN, '-p', 'tcp',
             '--tcp-flags', 'ALL', 'ALL', '-j', 'DROP'],

            # FIN scan
            ['-A', self.CHAIN, '-p', 'tcp',
             '--tcp-flags', 'ALL', 'FIN', '-j', 'DROP'],

            # SSH brute force: 60s içinde 5 yeni bağlantı → düşür
            ['-A', self.CHAIN, '-p', 'tcp', '--dport', '22',
             '-m', 'state', '--state', 'NEW',
             '-m', 'recent', '--name', 'ssh_bf', '--set'],
            ['-A', self.CHAIN, '-p', 'tcp', '--dport', '22',
             '-m', 'state', '--state', 'NEW',
             '-m', 'recent', '--name', 'ssh_bf',
             '--rcheck', '--seconds', '60', '--hitcount', '5',
             '-j', 'LOG', '--log-prefix', 'IDS_SSH_BF: '],
            ['-A', self.CHAIN, '-p', 'tcp', '--dport', '22',
             '-m', 'state', '--state', 'NEW',
             '-m', 'recent', '--name', 'ssh_bf',
             '--rcheck', '--seconds', '60', '--hitcount', '5', '-j', 'DROP'],

            # FTP brute force
            ['-A', self.CHAIN, '-p', 'tcp', '--dport', '21',
             '-m', 'state', '--state', 'NEW',
             '-m', 'recent', '--name', 'ftp_bf', '--set'],
            ['-A', self.CHAIN, '-p', 'tcp', '--dport', '21',
             '-m', 'state', '--state', 'NEW',
             '-m', 'recent', '--name', 'ftp_bf',
             '--rcheck', '--seconds', '60', '--hitcount', '5', '-j', 'DROP'],

            # ICMP flood: 2/s'den fazlasını düşür
            ['-A', self.CHAIN, '-p', 'icmp',
             '-m', 'limit', '--limit', '2/s', '--limit-burst', '5', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-p', 'icmp', '-j', 'DROP'],

            # Parçalanmış paketler
            ['-A', self.CHAIN, '-f', '-j', 'DROP'],

            # Zincir sonu: devam et
            ['-A', self.CHAIN, '-j', 'RETURN'],
        ]

        for rule in rules:
            r = _run(['iptables'] + rule)
            if r.returncode != 0:
                logger.debug(f"Kural atlandı: {' '.join(rule)} → {r.stderr.strip()}")

        logger.info(f"iptables IDS_IPS zinciri hazır. Arayüz: {CONFIG['suricata']['interface']}")

        # Daha önce kaydedilmiş engelleri yeniden uygula
        with self.lock:
            for ip, info in list(self.blocked_ips.items()):
                self._insert_drop(ip)

        return True

    # ------------------------------------------------------------------ #
    #  Engelleme / Engel kaldırma                                         #
    # ------------------------------------------------------------------ #

    def block_ip(self, ip: str, reason: str,
                 duration: int = None, permanent: bool = False) -> bool:

        if not self._valid_ip(ip):
            return False
        if ip in self.whitelist:
            logger.debug(f"Whitelist'te, atlandı: {ip}")
            return False

        duration = duration or CONFIG['blocking']['block_duration']

        with self.lock:
            self.violation_cnt[ip] += 1

            if self.violation_cnt[ip] >= CONFIG['blocking']['permanent_block_threshold']:
                permanent = True

            if ip in self.blocked_ips:
                if permanent and not self.blocked_ips[ip].get('permanent'):
                    self.blocked_ips[ip]['permanent'] = True
                    logger.warning(f"[KALICI ENGEL] {ip} — {reason}")
                return True

            if CONFIG['blocking']['enabled']:
                self._insert_drop(ip)

            self.blocked_ips[ip] = {
                'time':      time.time(),
                'reason':    reason,
                'permanent': permanent,
                'duration':  duration,
                'count':     self.violation_cnt[ip],
            }
            self.stats['total_blocked'] += 1

            label = "KALICI" if permanent else f"{duration//60} dk"
            logger.warning(
                f"[ENGELLENDİ] {ip} | {reason[:70]} | "
                f"Süre: {label} | İhlal #{self.violation_cnt[ip]}"
            )
            self._save_state()
        return True

    def unblock_ip(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            # Hem DROP hem LOG kuralını kaldır
            _run(['iptables', '-D', self.CHAIN, '-s', ip, '-j', 'DROP'])
            _run(['iptables', '-D', self.CHAIN, '-s', ip, '-j', 'LOG',
                  '--log-prefix', f'NETSPECTER_BLOCK:{ip}: '])
            del self.blocked_ips[ip]
            logger.info(f"[ENGEL KALDIRILDI] {ip}")
            self._save_state()
        return True

    def cleanup_expired_blocks(self):
        """Süresi dolan geçici engelleri kaldır"""
        now = time.time()
        to_remove = [
            ip for ip, info in self.blocked_ips.items()
            if not info.get('permanent')
            and now - info['time'] > info.get('duration', CONFIG['blocking']['block_duration'])
        ]
        for ip in to_remove:
            logger.info(f"Engel süresi doldu: {ip}")
            self.unblock_ip(ip)

    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            return ip in self.blocked_ips

    def increment_alert(self, attack_type: str):
        with self.lock:
            self.stats['total_alerts'] += 1
            self.stats['attack_types'][attack_type] += 1

    def get_stats(self) -> dict:
        with self.lock:
            return {
                'total_blocked':     self.stats['total_blocked'],
                'total_alerts':      self.stats['total_alerts'],
                'currently_blocked': len(self.blocked_ips),
                'permanent_blocks':  sum(1 for i in self.blocked_ips.values() if i.get('permanent')),
                'attack_types':      dict(self.stats['attack_types']),
                'blocked_list':      list(self.blocked_ips.keys()),
            }

    # ------------------------------------------------------------------ #
    #  Yardımcı fonksiyonlar                                              #
    # ------------------------------------------------------------------ #

    def _insert_drop(self, ip: str):
        """IDS_IPS zincirinin başına DROP kuralı ekle"""
        _run(['iptables', '-I', self.CHAIN, '1', '-s', ip, '-j', 'LOG',
              '--log-prefix', f'NETSPECTER_BLOCK:{ip}: '])
        _run(['iptables', '-I', self.CHAIN, '2', '-s', ip, '-j', 'DROP'])

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _save_state(self):
        try:
            os.makedirs('/var/log/netspecter', exist_ok=True)
            with open('/var/log/netspecter/state.json', 'w') as f:
                json.dump({
                    'blocked_ips':      self.blocked_ips,
                    'violation_counts': dict(self.violation_cnt),
                }, f, indent=2)
        except Exception as e:
            logger.error(f"State kaydedilemedi: {e}")

    def _load_state(self):
        path = '/var/log/netspecter/state.json'
        try:
            if os.path.exists(path):
                with open(path) as f:
                    data = json.load(f)
                self.blocked_ips   = data.get('blocked_ips', {})
                self.violation_cnt = defaultdict(int, data.get('violation_counts', {}))
                logger.info(f"Önceki state yüklendi: {len(self.blocked_ips)} engellenmiş IP")
        except Exception as e:
            logger.debug(f"State yüklenemedi (ilk çalıştırma olabilir): {e}")
