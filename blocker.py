#!/usr/bin/env python3
"""
IP Engelleme Modülü
iptables IDS_IPS zincirini güvenli şekilde yönetir
Tüm engeller kalıcıdır, sadece manuel kaldırılabilir.
"""

import subprocess
import logging
import time
import json
import os
import ipaddress
from collections import defaultdict
from threading import Lock

from config import CONFIG

try:
    from database import save_block, save_unblock, get_active_blocks, get_whitelist_ips
    DB_ENABLED = True
except ImportError:
    DB_ENABLED = False

logger = logging.getLogger(__name__)


def _run(cmd: list, check=False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


class IPBlocker:

    CHAIN = 'IDS_IPS'

    def __init__(self):
        self.blocked_ips = {}         # ip → {time, reason}
        self.lock        = Lock()
        self.stats       = {
            'total_blocked': 0,
            'total_alerts':  0,
            'attack_types':  defaultdict(int),
        }
        self.whitelist = self._load_whitelist()
        self._load_state()

    def _load_whitelist(self) -> set:
        if DB_ENABLED:
            try:
                ips = get_whitelist_ips()
                if ips:
                    logger.info(f"Whitelist DB'den yüklendi: {len(ips)} IP")
                    return ips
            except Exception as e:
                logger.debug(f"DB whitelist yüklenemedi: {e}")
        return set(CONFIG['blocking']['whitelist'])

    def refresh_whitelist(self):
        self.whitelist = self._load_whitelist()
        logger.info(f"Whitelist yenilendi: {len(self.whitelist)} IP")

    # ── iptables ────────────────────────────────────────────────────────

    def setup_initial_rules(self):
        logger.info("iptables kuralları kuruluyor...")

        _run(['iptables', '-D', 'INPUT',   '-j', self.CHAIN])
        _run(['iptables', '-D', 'FORWARD', '-j', self.CHAIN])
        _run(['iptables', '-F', self.CHAIN])
        _run(['iptables', '-X', self.CHAIN])

        r = _run(['iptables', '-N', self.CHAIN])
        if r.returncode != 0:
            logger.error(f"Zincir oluşturulamadı: {r.stderr}")
            return False

        _run(['iptables', '-I', 'INPUT',   '1', '-j', self.CHAIN])
        _run(['iptables', '-I', 'FORWARD', '1', '-j', self.CHAIN])

        rules = [
            ['-A', self.CHAIN, '-i', 'lo', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'RETURN'],

            ['-A', self.CHAIN, '-p', 'tcp', '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'],
            ['-A', self.CHAIN, '-p', 'tcp', '--tcp-flags', 'ALL', 'ALL',  '-j', 'DROP'],
            ['-A', self.CHAIN, '-p', 'tcp', '--tcp-flags', 'ALL', 'FIN',  '-j', 'DROP'],

            ['-A', self.CHAIN, '-p', 'icmp', '-m', 'limit', '--limit', '2/s', '--limit-burst', '5', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-p', 'icmp', '-j', 'DROP'],
            ['-A', self.CHAIN, '-f', '-j', 'DROP'],
            ['-A', self.CHAIN, '-j', 'RETURN'],
        ]

        for rule in rules:
            r = _run(['iptables'] + rule)
            if r.returncode != 0:
                logger.debug(f"Kural atlandı: {' '.join(rule)} → {r.stderr.strip()}")

        logger.info("iptables IDS_IPS zinciri hazır.")

        with self.lock:
            for ip in list(self.blocked_ips.keys()):
                self._insert_drop(ip)

        return True

    # ── Engelleme ────────────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str, **kwargs) -> bool:
        if not self._valid_ip(ip):
            return False

        # Whitelist'i DB'den kontrol et
        if DB_ENABLED:
            try:
                self.whitelist = get_whitelist_ips()
            except Exception:
                pass

        if ip in self.whitelist:
            logger.debug(f"Whitelist'te, atlandı: {ip}")
            return False

        with self.lock:
            if ip in self.blocked_ips:
                # DB'de hala engelli mi kontrol et
                if DB_ENABLED:
                    try:
                        blocks = get_active_blocks()
                        active_ips = {str(b['ip']) for b in blocks}
                        if ip not in active_ips:
                            # Dashboard'dan kaldırılmış, dict'ten de sil
                            del self.blocked_ips[ip]
                        else:
                            return True
                    except Exception:
                        return True
                else:
                    return True

            if CONFIG['blocking']['enabled']:
                self._insert_drop(ip)

            self.blocked_ips[ip] = {
                'time':   time.time(),
                'reason': reason,
            }
            self.stats['total_blocked'] += 1

            # DB'ye kaydet
            if DB_ENABLED:
                try:
                    attack_type = reason.split('|')[0].strip()
                    save_block(ip, reason, attack_type)
                except Exception as e:
                    logger.debug(f"DB block kayıt hatası: {e}")

            logger.warning(f"[ENGELLENDİ] {ip} | {reason[:70]}")
            self._save_state()
        return True

    def unblock_ip(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            _run(['iptables', '-D', self.CHAIN, '-s', ip, '-j', 'DROP'])
            _run(['iptables', '-D', self.CHAIN, '-s', ip, '-j', 'LOG',
                  '--log-prefix', f'NETSPECTER_BLOCK:{ip}: '])
            del self.blocked_ips[ip]
            logger.info(f"[ENGEL KALDIRILDI] {ip}")

            if DB_ENABLED:
                try:
                    save_unblock(ip)
                except Exception as e:
                    logger.debug(f"DB unblock kayıt hatası: {e}")

            self._save_state()
        return True

    def cleanup_expired_blocks(self):
        """Tüm engeller kalıcı, temizlenecek bir şey yok."""
        pass

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
                'attack_types':      dict(self.stats['attack_types']),
                'blocked_list':      list(self.blocked_ips.keys()),
            }

    # ── Yardımcılar ──────────────────────────────────────────────────────

    def _insert_drop(self, ip: str):
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
                json.dump({'blocked_ips': self.blocked_ips}, f, indent=2)
        except Exception as e:
            logger.error(f"State kaydedilemedi: {e}")

    def _load_state(self):
        if DB_ENABLED:
            try:
                blocks = get_active_blocks()
                for b in blocks:
                    ip = str(b['ip'])
                    self.blocked_ips[ip] = {
                        'time':   b['blocked_at'].timestamp() if hasattr(b['blocked_at'], 'timestamp') else time.time(),
                        'reason': b.get('reason', ''),
                    }
                logger.info(f"DB'den yüklendi: {len(self.blocked_ips)} engellenmiş IP")
                return
            except Exception as e:
                logger.debug(f"DB yüklenemedi, state.json deneniyor: {e}")

        path = '/var/log/netspecter/state.json'
        try:
            if os.path.exists(path):
                with open(path) as f:
                    data = json.load(f)
                self.blocked_ips = data.get('blocked_ips', {})
                logger.info(f"state.json'dan yüklendi: {len(self.blocked_ips)} engellenmiş IP")
        except Exception as e:
            logger.debug(f"State yüklenemedi: {e}")
