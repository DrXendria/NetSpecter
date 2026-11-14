#!/usr/bin/env python3
"""
IP Engelleme Modülü
iptables / ip6tables IDS_IPS zincirini güvenli şekilde yönetir.
"""

import subprocess
import logging
import time
import ipaddress
from collections import defaultdict
from threading import Lock

from config import CONFIG

logger = logging.getLogger(__name__)

CHAIN = 'IDS_IPS'


def _run(cmd: list, check=False) -> subprocess.CompletedProcess:
    """Sessiz subprocess çalıştır"""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


# ── Paylaşılan iptables yardımcıları (dashboard.py ve manager.py de kullanır) ──

def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ipt_bin(ip: str) -> str:
    """IP sürümüne göre iptables veya ip6tables döndürür."""
    return 'ip6tables' if ipaddress.ip_address(ip).version == 6 else 'iptables'


def _log_rule(ip: str) -> list:
    return ['-s', ip, '-j', 'LOG', '--log-prefix', f'NETSPECTER_BLOCK:{ip}: ']


def _drop_rule(ip: str) -> list:
    return ['-s', ip, '-j', 'DROP']


def add_drop_rules(ip: str) -> bool:
    """Zincirin başına LOG + DROP ekler. Kural zaten varsa tekrar eklemez."""
    ipt = ipt_bin(ip)
    if _run([ipt, '-C', CHAIN] + _drop_rule(ip)).returncode == 0:
        return True
    _run([ipt, '-I', CHAIN, '1'] + _log_rule(ip))
    r = _run([ipt, '-I', CHAIN, '2'] + _drop_rule(ip))
    if r.returncode != 0:
        logger.error(f"{ipt} DROP kuralı eklenemedi ({ip}): {r.stderr.strip()}")
        return False
    return True


def remove_drop_rules(ip: str):
    """IP'ye ait tüm LOG/DROP kurallarını (mükerrerler dahil) kaldırır."""
    ipt = ipt_bin(ip)
    for rule in (_drop_rule(ip), _log_rule(ip)):
        for _ in range(50):   # güvenlik sınırı
            if _run([ipt, '-D', CHAIN] + rule).returncode != 0:
                break


class IPBlocker:

    CHAIN = CHAIN

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
        """IDS_IPS zincirini iptables ve ip6tables için sıfırdan kur"""
        logger.info("iptables kuralları kuruluyor...")

        ok_v4 = self._setup_chain('iptables', required=True)
        if not ok_v4:
            return False
        self._setup_chain('ip6tables', required=False)

        if not CONFIG['blocking']['enabled']:
            logger.info("Engelleme devre dışı (IDS Modu). Mevcut zincirler temizlendi, sadece izleme yapılacak.")
            return True

        logger.info(f"iptables IDS_IPS zinciri hazır. Arayüz: {CONFIG['suricata']['interface']}")

        # Daha önce kaydedilmiş engelleri yeniden uygula
        with self.lock:
            for ip in list(self.blocked_ips):
                add_drop_rules(ip)

        return True

    def _setup_chain(self, ipt: str, required: bool) -> bool:
        if _run(['which', ipt]).returncode != 0:
            if required:
                logger.error(f"{ipt} bulunamadı!")
            else:
                logger.warning(f"{ipt} bulunamadı, IPv6 engelleme devre dışı.")
            return not required

        # Önce INPUT/FORWARD'dan zincire yönlendirmeleri kaldır (hata olursa sorun yok)
        _run([ipt, '-D', 'INPUT',   '-j', self.CHAIN])
        _run([ipt, '-D', 'FORWARD', '-j', self.CHAIN])
        _run([ipt, '-F', self.CHAIN])
        _run([ipt, '-X', self.CHAIN])

        if not CONFIG['blocking']['enabled']:
            return True

        r = _run([ipt, '-N', self.CHAIN])
        if r.returncode != 0:
            log = logger.error if required else logger.warning
            log(f"{ipt}: zincir oluşturulamadı: {r.stderr.strip()}")
            return not required

        _run([ipt, '-I', 'INPUT',   '1', '-j', self.CHAIN])
        _run([ipt, '-I', 'FORWARD', '1', '-j', self.CHAIN])

        rules = [
            ['-A', self.CHAIN, '-i', 'lo', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'RETURN'],
            ['-A', self.CHAIN, '-j', 'RETURN'],
        ]
        for rule in rules:
            r = _run([ipt] + rule)
            if r.returncode != 0:
                logger.debug(f"Kural atlandı: {ipt} {' '.join(rule)} → {r.stderr.strip()}")
        return True

    # ------------------------------------------------------------------ #
    #  Engelleme / Engel kaldırma                                         #
    # ------------------------------------------------------------------ #

    def block_ip(self, ip: str, reason: str,
                 duration: int = None, permanent: bool = False) -> bool:

        if not valid_ip(ip):
            return False

        if ip in ('0.0.0.0', '255.255.255.255'):
            return False

        # MySQL'den canlı Whitelist kontrolü
        try:
            from database import get_whitelist_ips
            if ip in get_whitelist_ips():
                logger.info(f"🛡️  BEYAZ LİSTE: {ip} veritabanı listesinde olduğu için engelleme atlandı.")
                return False
        except Exception:
            pass

        if ip in self.whitelist:
            logger.info(f"🛡️  BEYAZ LİSTE: {ip} statik listede (config.py) olduğu için engelleme atlandı.")
            return False

        # Varsayılan: tüm engellemeler Dashboard'dan kaldırılana kadar kalıcı
        if CONFIG['blocking'].get('persist_until_manual_unblock', True):
            permanent = True
        duration = duration or CONFIG['blocking']['block_duration']

        with self.lock:
            self.violation_cnt[ip] += 1

            if self.violation_cnt[ip] >= CONFIG['blocking']['permanent_block_threshold']:
                permanent = True

            if ip in self.blocked_ips:
                logger.info(f"ℹ️  [ZATEN ENGELLİ] {ip} hafızada var, iptables kuralı kontrol ediliyor.")
                if CONFIG['blocking']['enabled']:
                    add_drop_rules(ip)
                return True

            if CONFIG['blocking']['enabled']:
                add_drop_rules(ip)
            else:
                logger.info(f"🛡️  [IDS MODU] {ip} engellenmedi, sadece loglandı (blocking.enabled=False)")

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
                save_block(ip, reason, attack_type, permanent=permanent, duration=duration)
            except Exception as e:
                logger.error(f"Veritabanına engel kaydedilemedi: {e}")

        return True

    def unblock_ip(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            remove_drop_rules(ip)
            del self.blocked_ips[ip]
            logger.info(f"[ENGEL KALDIRILDI] {ip}")

            try:
                from database import save_unblock
                save_unblock(ip)
            except Exception as e:
                logger.error(f"Veritabanında engel kaldırılamadı: {e}")

        return True

    def cleanup_expired_blocks(self):
        """Süresi dolan geçici engelleri kaldır"""
        now = time.time()
        with self.lock:
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

    def sync_with_db(self):
        """Veritabanıyla senkronize ol:
        - Dashboard/CLI'dan kaldırılan engelleri hafızadan ve iptables'dan temizle
        - CLI'dan (netspecter-manager block) eklenen engelleri hafızaya al
        """
        try:
            from database import get_active_blocks
            active_blocks = get_active_blocks()
            db_ips = {b['ip'] for b in active_blocks}
            now = time.time()

            with self.lock:
                # Çok yeni engelleri atla (DB okuması ile kilit arasında eklenmiş olabilir)
                to_sync_remove = [ip for ip, info in self.blocked_ips.items()
                                  if ip not in db_ips and now - info['time'] > 15]
                for b in active_blocks:
                    if b['ip'] not in self.blocked_ips:
                        self.blocked_ips[b['ip']] = self._info_from_row(b)
                        if CONFIG['blocking']['enabled']:
                            add_drop_rules(b['ip'])
                        logger.info(f"🔄 [SYNC] {b['ip']} veritabanından engel listesine eklendi.")

            # Kilitten çıkıp temizliği yapalım (unblock_ip kilidi kendisi alır)
            for ip in to_sync_remove:
                logger.info(f"🔄 [SYNC] {ip} Dashboard üzerinden kaldırılmış, hafıza temizleniyor.")
                self.unblock_ip(ip)

        except Exception as e:
            logger.error(f"Veritabanı senkronizasyon hatası: {e}")

    # ------------------------------------------------------------------ #
    #  Yardımcı fonksiyonlar                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        return valid_ip(ip)

    def _info_from_row(self, b: dict) -> dict:
        blocked_at = b['blocked_at'].timestamp()
        permanent  = bool(b.get('permanent', 1))
        expires_at = b.get('expires_at')
        if not permanent and expires_at is not None:
            duration = max(0, int(expires_at.timestamp() - blocked_at))
        else:
            duration = CONFIG['blocking']['block_duration']
        return {
            'time':      blocked_at,
            'reason':    b.get('reason') or '',
            'duration':  duration,
            'permanent': permanent,
            'count':     self.violation_cnt.get(b['ip'], 1),
        }

    def _load_state(self):
        try:
            from database import get_active_blocks, get_conn
            blocks = get_active_blocks()

            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT ip, COUNT(*) as cnt FROM blocked_ips GROUP BY ip")
                    for row in cur.fetchall():
                        self.violation_cnt[row['ip']] = row['cnt']

            for b in blocks:
                self.blocked_ips[b['ip']] = self._info_from_row(b)
            logger.info(f"MySQL Veritabanından state yüklendi: {len(self.blocked_ips)} aktif engellenmiş IP")
        except Exception as e:
            logger.error(f"Veritabanından state yüklenemedi: {e}")
