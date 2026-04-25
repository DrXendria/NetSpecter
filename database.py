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


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            for stmt in SCHEMA:
                cur.execute(stmt)

    # Varsayılan admin
    if not get_user('admin'):
        create_user('admin', 'netspecter')
        print('[DB] Varsayılan admin oluşturuldu. (admin / netspecter)')

    # Varsayılan whitelist girişleri
    for ip, desc in [('127.0.0.1', 'Localhost'), ('::1', 'Localhost IPv6')]:
        try:
            add_whitelist(ip, desc)
        except Exception:
            pass

    print('[DB] Veritabanı hazır.')


# ── KULLANICI YÖNETİMİ ───────────────────────────────────────────────────

def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


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


def verify_user(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False
    return user['password_hash'] == _hash_password(password, user['salt'])


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
    salt = secrets.token_hex(16)
    password_hash = _hash_password(new_password, salt)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s, salt=%s WHERE username=%s",
                (password_hash, salt, username)
            )
    return True, 'Şifre değiştirildi'


# ── ALERT ────────────────────────────────────────────────────────────────

# ── ENGELLEME ────────────────────────────────────────────────────────────

def save_block(ip: str, reason: str, attack_type: str) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE blocked_ips SET unblocked_at=NOW() WHERE ip=%s AND unblocked_at IS NULL",
                (ip,)
            )
            cur.execute(
                """INSERT INTO blocked_ips (ip, reason, attack_type)
                   VALUES (%s, %s, %s)""",
                (ip, reason, attack_type)
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
