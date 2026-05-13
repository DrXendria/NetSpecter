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

        if not CONFIG['blocking']['enabled']:
            logger.info("Engelleme devre dışı (IDS Modu). Mevcut zincirler temizlendi, sadece izleme yapılacak.")
            return True

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
            
        # MySQL'den canlı Whitelist kontrolü
        try:
            from database import get_whitelist
            db_wl = [r['ip'] for r in get_whitelist()]
            if ip in db_wl or ip == '0.0.0.0' or ip == '255.255.255.255':
                logger.debug(f"Veritabanı Whitelist'te, atlandı: {ip}")
                return False
        except Exception:
            pass

        if ip in self.whitelist:
            logger.debug(f"Statik Whitelist'te, atlandı: {ip}")
            return False

        # Kullanıcı isteği: Tüm engellemeler Dashboard'dan kaldırılana kadar kalıcı olacak
        permanent = True
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
            
            # MySQL Veritabanına kaydet
            try:
                from database import save_block
                attack_type = reason.split('|')[0].strip() if '|' in reason else reason.split()[0]
                save_block(ip, reason, attack_type)
            except Exception as e:
                logger.error(f"Veritabanına engel kaydedilemedi: {e}")

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
            
            # MySQL Veritabanından kaldır
            try:
                from database import save_unblock
                save_unblock(ip)
            except Exception as e:
                logger.error(f"Veritabanında engel kaldırılamadı: {e}")

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
        # Artık veritabanı anlık yazıldığı için json dosyasına ihtiyaç yok.
        pass

    def _load_state(self):
        try:
            from database import get_active_blocks, get_conn
            blocks = get_active_blocks()
            
            # violation_counts hesapla
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT ip, COUNT(*) as cnt FROM blocked_ips GROUP BY ip")
                    for row in cur.fetchall():
                        self.violation_cnt[row['ip']] = row['cnt']

            for b in blocks:
                self.blocked_ips[b['ip']] = {
                    'time': b['blocked_at'].timestamp(),
                    'reason': b['reason'] or '',
                    'duration': CONFIG['blocking']['block_duration'],
                    'permanent': True,  # Bütün yüklenen engeller kalıcı sayılacak
                    'count': self.violation_cnt.get(b['ip'], 1)
                }
            logger.info(f"MySQL Veritabanından state yüklendi: {len(self.blocked_ips)} aktif engellenmiş IP")
        except Exception as e:
            logger.error(f"Veritabanından state yüklenemedi: {e}")
