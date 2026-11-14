#!/usr/bin/env python3
"""
NetSpecter — MySQL Veritabanı Modülü

Kurulum:
  sudo apt install mysql-server python3-dev default-libmysqlclient-dev -y
  pip3 install mysqlclient --break-system-packages
  sudo mysql_secure_installation
  sudo mysql -e "CREATE DATABASE netspecter CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  sudo mysql -e "CREATE USER 'netspecter'@'localhost' IDENTIFIED BY 'netspecter';"
  sudo mysql -e "GRANT ALL PRIVILEGES ON netspecter.* TO 'netspecter'@'localhost';"
  sudo mysql -e "FLUSH PRIVILEGES;"
"""

import os
import hmac
import hashlib
import secrets
import MySQLdb
import MySQLdb.cursors
from contextlib import contextmanager
from pathlib import Path


def _load_env():
    candidates = [
        Path('/opt/netspecter/.env'),
        Path(__file__).parent / '.env',
        Path('.env'),
    ]
    for p in candidates:
        if p.exists():
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    key, _, val = line.partition('=')
                    os.environ.setdefault(key.strip(), val.strip())
            break

_load_env()

DB_CONFIG = {
    'host':   os.getenv('DB_HOST',     'localhost'),
    'port':   int(os.getenv('DB_PORT', '3306')),
    'db':     os.getenv('DB_NAME',     'netspecter'),
    'user':   os.getenv('DB_USER',     'netspecter'),
    'passwd': os.getenv('DB_PASSWORD', 'netspecter'),
    'charset': 'utf8mb4',
}


@contextmanager
def get_conn():
    conn = MySQLdb.connect(**DB_CONFIG, cursorclass=MySQLdb.cursors.DictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── ŞEMA ─────────────────────────────────────────────────────────────────

SCHEMA = [
"""CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    salt          VARCHAR(64) NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

"""CREATE TABLE IF NOT EXISTS alerts (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    src_ip      VARCHAR(45) NOT NULL,
    dest_port   INT,
    attack_type VARCHAR(64),
    severity    INT,
    signature   TEXT,
    category    TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_src_ip (src_ip),
    INDEX idx_created_at (created_at),
    INDEX idx_attack_type (attack_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

"""CREATE TABLE IF NOT EXISTS blocked_ips (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    ip           VARCHAR(45) NOT NULL,
    reason       TEXT,
    attack_type  VARCHAR(64),
    blocked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    unblocked_at DATETIME DEFAULT NULL,
    INDEX idx_ip (ip),
    INDEX idx_blocked_at (blocked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

"""CREATE TABLE IF NOT EXISTS ddos_events (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(64),
    ip_count    INT,
    time_window INT,
    sample_ips  TEXT,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",

"""CREATE TABLE IF NOT EXISTS whitelist (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    ip          VARCHAR(45) UNIQUE NOT NULL,
    description VARCHAR(128),
    added_at    DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
]


def _ensure_column(cur, table: str, column: str, ddl: str):
    """Eski kurulumlar için eksik kolonu ekler (MySQL & MariaDB uyumlu)."""
    cur.execute(
        """SELECT COUNT(*) AS c FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s""",
        (table, column)
    )
    if cur.fetchone()['c'] == 0:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            for stmt in SCHEMA:
                cur.execute(stmt)
            # Migration: süreli / kalıcı engel desteği
            _ensure_column(cur, 'blocked_ips', 'permanent',  'TINYINT(1) NOT NULL DEFAULT 1')
            _ensure_column(cur, 'blocked_ips', 'expires_at', 'DATETIME DEFAULT NULL')

    # Varsayılan admin (şifre .env → DASHBOARD_ADMIN_PASSWORD, yoksa 'netspecter')
    if not get_user('admin'):
        admin_pass = os.getenv('DASHBOARD_ADMIN_PASSWORD') or 'netspecter'
        create_user('admin', admin_pass)
        if admin_pass == 'netspecter':
            print('[DB] Varsayılan admin oluşturuldu. (admin / netspecter) — LÜTFEN DEĞİŞTİRİN!')
        else:
            print('[DB] Admin kullanıcısı .env içindeki DASHBOARD_ADMIN_PASSWORD ile oluşturuldu.')

    # Varsayılan whitelist girişleri
    for ip, desc in [('127.0.0.1', 'Localhost'), ('::1', 'Localhost IPv6')]:
        try:
            add_whitelist(ip, desc)
        except Exception:
            pass

    print('[DB] Veritabanı hazır.')


# ── KULLANICI YÖNETİMİ ───────────────────────────────────────────────────

PBKDF2_ITERATIONS = 200_000
PBKDF2_PREFIX     = 'pbkdf2_sha256'


def _hash_password(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 ile hash üretir. Format: pbkdf2_sha256$<iter>$<hex>"""
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f'{PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${dk.hex()}'


def _check_password(password: str, salt: str, stored: str) -> bool:
    if stored.startswith(PBKDF2_PREFIX + '$'):
        try:
            _, iters, hexdigest = stored.split('$', 2)
            dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), int(iters))
            return hmac.compare_digest(dk.hex(), hexdigest)
        except ValueError:
            return False
    # Eski (v2.0) format: sha256(salt + password)
    legacy = hashlib.sha256((salt + password).encode()).hexdigest()
    return hmac.compare_digest(legacy, stored)


def create_user(username: str, password: str) -> bool:
    salt = secrets.token_hex(16)
    password_hash = _hash_password(password, salt)
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                    (username, password_hash, salt)
                )
        return True
    except MySQLdb.IntegrityError:
        return False


def get_user(username: str) -> dict | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            return cur.fetchone()


def _set_password(username: str, password: str):
    salt = secrets.token_hex(16)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s, salt=%s WHERE username=%s",
                (_hash_password(password, salt), salt, username)
            )


def verify_user(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False
    if not _check_password(password, user['salt'], user['password_hash']):
        return False
    # Eski formatta saklanan şifreyi PBKDF2'ye yükselt
    if not user['password_hash'].startswith(PBKDF2_PREFIX + '$'):
        try:
            _set_password(username, password)
        except Exception:
            pass
    return True


def change_username(old_username: str, new_username: str, password: str) -> tuple[bool, str]:
    if not verify_user(old_username, password):
        return False, 'Mevcut şifre hatalı'
    if get_user(new_username):
        return False, 'Bu kullanıcı adı zaten kullanılıyor'
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET username=%s WHERE username=%s",
                (new_username, old_username)
            )
    return True, 'Kullanıcı adı değiştirildi'


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    if not verify_user(username, old_password):
        return False, 'Mevcut şifre hatalı'
    if len(new_password) < 8:
        return False, 'Yeni şifre en az 8 karakter olmalı'
    _set_password(username, new_password)
    return True, 'Şifre değiştirildi'


# ── ALERT ────────────────────────────────────────────────────────────────

def save_alert(src_ip: str, dest_port: int, attack_type: str, severity: int, signature: str, category: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (src_ip, dest_port, attack_type, severity, signature, category)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (src_ip, dest_port, attack_type, severity, signature, category))

def get_alerts(limit=200) -> list:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT %s", (limit,))
            return list(cur.fetchall())

def get_alert_stats() -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as total FROM alerts WHERE created_at >= NOW() - INTERVAL 24 HOUR")
            total = cur.fetchone()['total']
            
            cur.execute("SELECT attack_type, COUNT(*) as cnt FROM alerts WHERE created_at >= NOW() - INTERVAL 24 HOUR GROUP BY attack_type")
            dist = {r['attack_type']: r['cnt'] for r in cur.fetchall()}
            
            # Son 24 saatin verisi timeline için
            cur.execute("""
                SELECT DATE_FORMAT(created_at, '%H:%i') as time, COUNT(*) as count 
                FROM alerts 
                WHERE created_at >= NOW() - INTERVAL 24 HOUR
                GROUP BY time ORDER BY time ASC
            """)
            timeline = list(cur.fetchall())
            
            cur.execute("SELECT COUNT(*) as total_all FROM alerts")
            total_all = cur.fetchone()['total_all']
            
            return {
                'total': total,
                'total_all': total_all,
                'dist': dist,
                'timeline': timeline
            }

# ── ENGELLEME ────────────────────────────────────────────────────────────

def get_cli_stats() -> dict:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as c, SUM(IF(permanent = 1, 1, 0)) as p FROM blocked_ips WHERE unblocked_at IS NULL")
            res = cur.fetchone()
            blocked_count = res['c'] or 0
            permanent_count = res['p'] or 0
            
            cur.execute("""
                SELECT ip, COUNT(*) as cnt 
                FROM blocked_ips 
                GROUP BY ip 
                ORDER BY cnt DESC 
                LIMIT 3
            """)
            top_violations = [(r['ip'], r['cnt']) for r in cur.fetchall()]
            
            return {
                'blocked_count': blocked_count,
                'permanent_count': int(permanent_count),
                'top_violations': top_violations
            }

def save_block(ip: str, reason: str, attack_type: str,
               permanent: bool = True, duration: int | None = None) -> int:
    """Aktif engeli kaydeder. permanent=False ise expires_at = NOW() + duration."""
    expires_in = None if (permanent or not duration) else int(duration)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE blocked_ips SET unblocked_at=NOW() WHERE ip=%s AND unblocked_at IS NULL",
                (ip,)
            )
            cur.execute(
                """INSERT INTO blocked_ips (ip, reason, attack_type, permanent, expires_at)
                   VALUES (%s, %s, %s, %s,
                           IF(%s IS NULL, NULL, NOW() + INTERVAL %s SECOND))""",
                (ip, reason, attack_type, 1 if expires_in is None else 0,
                 expires_in, expires_in or 0)
            )
            return conn.insert_id()


def save_unblock(ip: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE blocked_ips SET unblocked_at=NOW() WHERE ip=%s AND unblocked_at IS NULL",
                (ip,)
            )


def get_active_blocks() -> list:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM blocked_ips
                WHERE unblocked_at IS NULL
                ORDER BY blocked_at DESC
            """)
            return list(cur.fetchall())


def get_violation_count(ip: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM blocked_ips WHERE ip=%s", (ip,))
            return cur.fetchone()['cnt']


# ── DDoS ─────────────────────────────────────────────────────────────────

def save_ddos_event(attack_type: str, ip_count: int, time_window: int, sample_ips: list):
    import json
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO ddos_events (attack_type, ip_count, time_window, sample_ips)
                   VALUES (%s, %s, %s, %s)""",
                (attack_type, ip_count, time_window, json.dumps(list(sample_ips)[:20]))
            )


# ── WHİTELİST ────────────────────────────────────────────────────────────

def get_whitelist() -> list:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM whitelist ORDER BY added_at DESC")
            return list(cur.fetchall())


def get_whitelist_ips() -> set:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ip FROM whitelist")
            return {r['ip'] for r in cur.fetchall()}


def add_whitelist(ip: str, description: str = '') -> bool:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO whitelist (ip, description) VALUES (%s, %s)",
                    (ip, description)
                )
        return True
    except MySQLdb.IntegrityError:
        return False


def remove_whitelist(ip: str) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM whitelist WHERE ip=%s", (ip,))
            return cur.rowcount > 0


def get_ip_report_data(ip: str) -> dict:
    """Belirli bir IP için detaylı rapor verisi toplar"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE src_ip = %s ORDER BY created_at DESC", (ip,))
            alerts = list(cur.fetchall())
            cur.execute("SELECT * FROM blocked_ips WHERE ip = %s ORDER BY blocked_at DESC", (ip,))
            blocks = list(cur.fetchall())
            return {
                'ip': ip,
                'alerts': alerts,
                'blocks': blocks,
                'violation_count': len(blocks)
            }


def get_daily_report_data() -> dict:
    """Son 24 saatlik sistem özetini toplar"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alerts WHERE created_at >= NOW() - INTERVAL 1 DAY")
            alerts = list(cur.fetchall())
            cur.execute("""
                SELECT src_ip, COUNT(*) as cnt FROM alerts 
                WHERE created_at >= NOW() - INTERVAL 1 DAY 
                GROUP BY src_ip ORDER BY cnt DESC LIMIT 5
            """)
            top_ips = list(cur.fetchall())
            cur.execute("SELECT COUNT(*) as cnt FROM blocked_ips WHERE blocked_at >= NOW() - INTERVAL 1 DAY")
            blocked_today = cur.fetchone()['cnt']
            
            return {
                'alerts_count': len(alerts),
                'top_ips': top_ips,
                'blocked_today': blocked_today,
                'alerts': alerts[:50]
            }


if __name__ == '__main__':
    print('[DB] Veritabanı başlatılıyor...')
    try:
        init_db()
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as c FROM users")
                print(f'[DB] Kullanıcılar : {cur.fetchone()["c"]}')
                cur.execute("SELECT COUNT(*) as c FROM alerts")
                print(f'[DB] Alertler     : {cur.fetchone()["c"]}')
                cur.execute("SELECT COUNT(*) as c FROM whitelist")
                print(f'[DB] Whitelist    : {cur.fetchone()["c"]}')
        print('[DB] Her şey hazır.')
    except Exception as e:
        print(f'[DB] HATA: {e}')
        print('\nKontrol listesi:')
        print('  sudo systemctl status mysql')
        print('  sudo mysql -e "CREATE DATABASE netspecter;"')
        print('  sudo mysql -e "CREATE USER \'netspecter\'@\'localhost\' IDENTIFIED BY \'netspecter\';"')
        print('  sudo mysql -e "GRANT ALL PRIVILEGES ON netspecter.* TO \'netspecter\'@\'localhost\';"')
        print('  sudo mysql -e "FLUSH PRIVILEGES;"')
