#!/usr/bin/env python3
"""
NetSpecter Dashboard — Flask Backend
Kullanım: sudo python3 dashboard.py
"""

import os
import signal
import subprocess
import sys
import json
import time
import threading
from datetime import datetime
from collections import deque
from pathlib import Path

import secrets
import ipaddress

sys.path.insert(0, '/opt/netspecter')
sys.path.insert(0, str(Path(__file__).resolve().parent))

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from functools import wraps
from flask_socketio import SocketIO, emit
from reporter import ReportGenerator
from monitor import classify, is_noisy          # tek sınıflandırma kaynağı
from blocker import valid_ip, remove_drop_rules
try:
    from database import (
        verify_user, get_alerts, get_active_blocks,
        get_alert_stats, save_unblock, init_db
    )
    DB_ENABLED = True
except ImportError as e:
    print(f"[UYARI] Veritabanı modülü yüklenemedi: {e}")
    print("[UYARI] Sistem JSON/Bellek fallback modunda çalışacak.")
    DB_ENABLED = False


def _load_secret_key() -> str:
    """FLASK_SECRET_KEY (.env) → yoksa kalıcı rastgele anahtar dosyası oluştur."""
    key = os.getenv('FLASK_SECRET_KEY')
    if key:
        return key
    base = Path('/opt/netspecter') if Path('/opt/netspecter').is_dir() else Path(__file__).resolve().parent
    key_file = base / '.flask_secret'
    try:
        if key_file.exists():
            return key_file.read_text().strip()
        key = secrets.token_hex(32)
        key_file.write_text(key)
        os.chmod(key_file, 0o600)
        return key
    except OSError:
        # Yazılamıyorsa her başlatmada yeni anahtar (oturumlar yeniden başlatmada düşer)
        return secrets.token_hex(32)


app = Flask(__name__)
app.config['SECRET_KEY'] = _load_secret_key()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# DB yoksa kullanılan yedek giriş bilgileri (.env → DASHBOARD_ADMIN_PASSWORD)
DASHBOARD_USER = 'admin'
DASHBOARD_PASS = os.getenv('DASHBOARD_ADMIN_PASSWORD') or 'netspecter'

# cors_allowed_origins=None → yalnızca aynı origin (cross-site WebSocket engellenir)
socketio = SocketIO(app, async_mode='threading')

# Basit login brute-force koruması: IP başına 5 hatalı deneme / 5 dakika
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW    = 300
_login_fails: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def _login_blocked(ip: str) -> bool:
    now = time.time()
    with _login_lock:
        fails = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
        _login_fails[ip] = fails
        return len(fails) >= LOGIN_MAX_FAILS


def _login_failed(ip: str):
    with _login_lock:
        _login_fails.setdefault(ip, []).append(time.time())


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['GET'])
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    client_ip = request.remote_addr or '?'
    if _login_blocked(client_ip):
        return jsonify({'success': False, 'message': 'Too many attempts, try again later.'}), 429

    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    # DB varsa oradan doğrula, yoksa yedek bilgilere dön
    if DB_ENABLED:
        try:
            success = verify_user(username, password)
        except Exception as e:
            print(f"[DB HATA] verify_user başarısız: {e}")
            success = False
    else:
        success = secrets.compare_digest(username, DASHBOARD_USER) and \
                  secrets.compare_digest(password, DASHBOARD_PASS)

    if success:
        session.clear()
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'success': True})
    _login_failed(client_ip)
    return jsonify({'success': False}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# Bellekte tutulan son 200 alert
alert_buffer = deque(maxlen=200)
# Zaman bazlı istatistik (son 60 dakika, her dakika bir bucket)
timeline = deque(maxlen=60)

ATTACK_COLORS = {
    'nmap_scan':        '#f59e0b',   # Amber
    'brute_force_ssh':  '#ef4444',   # Kırmızı
    'brute_force_ftp':  '#f97316',   # Turuncu
    'brute_force_http': '#ec4899',   # Pembe
    'dos_attack':       '#a855f7',   # Mor
    'exploit':          '#dc2626',   # Koyu kırmızı
    'malware':          '#ff0000',   # Parlak kırmızı
    'web_attack':       '#06b6d4',   # Cyan
    'info_leak':        '#64748b',   # Gri
    'unknown':          '#334155',   # Koyu gri
}

ATTACK_LABELS = {
    'nmap_scan':        'Port Tarama',
    'brute_force_ssh':  'SSH Brute Force',
    'brute_force_ftp':  'FTP Brute Force',
    'brute_force_http': 'HTTP Brute Force',
    'dos_attack':       'DoS Saldırısı',
    'exploit':          'Exploit',
    'malware':          'Malware',
    'web_attack':       'Web Saldırısı',
    'info_leak':        'Bilgi Sızıntısı',
    'unknown':          'Bilinmeyen',
}


def get_state():
    try:
        path = '/var/log/netspecter/state.json'
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {'blocked_ips': {}, 'violation_counts': {}}


def get_system_stats():
    if DB_ENABLED:
        try:
            stats = get_alert_stats()
            blocks = get_active_blocks()
            from database import get_whitelist
            wl = get_whitelist()
            return {
                'blocked_count':   len(blocks),
                'permanent_count': sum(1 for b in blocks if b.get('permanent')),
                'total_alerts':    stats['total'],
                'total_all_time':  stats['total_all'],
                'attack_dist':     stats['dist'],
                'timeline':        stats['timeline'],
                'whitelist_count': len(wl),
            }
        except Exception as e:
            print(f"[DB HATA] get_system_stats başarısız: {e}")
            pass

    # Fallback: bellekten oku
    state = get_state()
    blocked = state.get('blocked_ips', {})
    violations = state.get('violation_counts', {})
    attack_dist = {}
    for info in blocked.values():
        reason = info.get('reason', 'unknown')
        tip = reason.split('|')[0].strip() if '|' in reason else 'unknown'
        attack_dist[tip] = attack_dist.get(tip, 0) + 1
    return {
        'blocked_count':   len(blocked),
        'permanent_count': sum(1 for i in blocked.values() if i.get('permanent')),
        'total_alerts':    sum(1 for _ in alert_buffer),
        'attack_dist':     attack_dist,
        'timeline':        [],
        'whitelist_count': 0,
    }


def get_blocked_ips():
    if DB_ENABLED:
        try:
            blocks = get_active_blocks()
            result = []
            seen_ips = set()
            for b in blocks:
                ip_str = str(b['ip'])
                if ip_str in seen_ips:
                    continue
                seen_ips.add(ip_str)
                
                dt = b.get('blocked_at')
                time_str = dt.strftime('%H:%M:%S') if hasattr(dt, 'strftime') else str(dt)[11:19]
                
                permanent = bool(b.get('permanent', 1))
                expires_at = b.get('expires_at')
                if permanent or not hasattr(expires_at, 'timestamp'):
                    remaining = '∞ Kalıcı'
                else:
                    secs = int(expires_at.timestamp() - time.time())
                    remaining = f'{max(0, secs) // 60} dk'

                result.append({
                    'ip':        ip_str,
                    'reason':    (b.get('reason') or '')[:60],
                    'permanent': permanent,
                    'remaining': remaining,
                    'count':     b.get('violation_count', 1),
                    'time':      time_str,
                })
            return sorted(result, key=lambda x: x['count'], reverse=True)
        except Exception as e:
            print(f"[DB HATA] get_blocked_ips başarısız: {e}")
            pass

    # Fallback: state.json
    state = get_state()
    blocked = state.get('blocked_ips', {})
    now = time.time()
    result = []
    for ip, info in blocked.items():
        if info.get('permanent'):
            remaining = '∞ Kalıcı'
        else:
            secs = int(info.get('duration', 3600) - (now - info.get('time', now)))
            remaining = f'{max(0, secs) // 60} dk'
        result.append({
            'ip':        ip,
            'reason':    info.get('reason', '')[:60],
            'permanent': info.get('permanent', False),
            'remaining': remaining,
            'count':     info.get('count', 1),
            'time':      datetime.fromtimestamp(info.get('time', now)).strftime('%H:%M:%S'),
        })
    return sorted(result, key=lambda x: x['count'], reverse=True)


# ── RAPORLAMA ───────────────────────────────────────────────────────────

@app.route('/api/report/daily')
@login_required
def report_daily():
    try:
        rep = ReportGenerator()
        pdf_path = rep.generate_daily_report()
        if pdf_path and os.path.exists(pdf_path):
            return send_file(pdf_path, as_attachment=True, download_name=f"gunluk_ozet_{datetime.now().strftime('%Y%m%d')}.pdf")
    except Exception as e:
        app.logger.error(f"Daily Report Error: {e}")
    return "Rapor oluşturulamadı", 500


@app.route('/api/report/ip/<ip>')
@login_required
def report_ip(ip):
    if not valid_ip(ip):
        return "Geçersiz IP", 400
    try:
        rep = ReportGenerator()
        pdf_path = rep.generate_ip_report(ip)
        if pdf_path and os.path.exists(pdf_path):
            return send_file(pdf_path, as_attachment=True, download_name=f"saldiri_raporu_{ip.replace('.','_').replace(':','_')}.pdf")
    except Exception as e:
        app.logger.error(f"IP Report Error: {e}")
    return "Rapor oluşturulamadı", 500


# ── API Endpointleri ────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html')


@app.route('/api/settings/change-password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json()
    old_pass = data.get('old_password', '')
    new_pass = data.get('new_password', '')

    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'Veritabanı bağlantısı aktif değil.'})

    try:
        from database import change_password
        username = session.get('username', 'admin')
        success, msg = change_password(username, old_pass, new_pass)
        return jsonify({'success': success, 'message': msg})
    except ImportError:
        return jsonify({'success': False, 'message': 'database.py eksik.'})


@app.route('/api/settings/change-username', methods=['POST'])
@login_required
def api_change_username():
    data = request.get_json()
    new_username = data.get('new_username', '')
    password = data.get('password', '')

    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'Veritabanı bağlantısı aktif değil.'})

    try:
        from database import change_username
        old_username = session.get('username', 'admin')
        success, msg = change_username(old_username, new_username, password)
        if success:
            session['username'] = new_username
        return jsonify({'success': success, 'message': msg})
    except ImportError:
        return jsonify({'success': False, 'message': 'database.py eksik.'})


@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())


@app.route('/api/blocked')
@login_required
def api_blocked():
    return jsonify(get_blocked_ips())


@app.route('/api/whitelist', methods=['GET', 'POST'])
@login_required
def api_whitelist():
    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'DB disabled'} if request.method == 'POST' else [])
        
    try:
        from database import get_whitelist, add_whitelist
        if request.method == 'POST':
            data = request.get_json() or {}
            ip = data.get('ip', '').strip()
            desc = data.get('description', '').strip()
            if not ip:
                return jsonify({'success': False, 'message': 'IP boş olamaz'})
            if not valid_ip(ip):
                return jsonify({'success': False, 'message': 'Geçersiz IP adresi'})
            success = add_whitelist(ip, desc)
            if success:
                socketio.emit('stats_update', get_system_stats())
            return jsonify({'success': success, 'message': 'Eklendi' if success else 'Zaten ekli'})
            
        rows = get_whitelist()
        return jsonify([{
            'ip': r['ip'],
            'description': r['description'] or '',
            'added_at': str(r.get('added_at', ''))[:10]
        } for r in rows])
    except Exception as e:
        if request.method == 'POST':
            return jsonify({'success': False, 'message': str(e)})
        pass
    return jsonify([])


@app.route('/api/whitelist/<path:ip>', methods=['DELETE'])
@login_required
def api_whitelist_remove(ip):
    if DB_ENABLED:
        try:
            from database import remove_whitelist
            success = remove_whitelist(ip)
            if success:
                socketio.emit('stats_update', get_system_stats())
            return jsonify({'success': success})
        except Exception:
            pass
    return jsonify({'success': False})


@app.route('/api/alerts')
@login_required
def api_alerts():
    if DB_ENABLED:
        try:
            rows = get_alerts(limit=200)
            result = []
            for r in rows:
                dt = r.get('created_at')
                time_str = dt.strftime('%d/%m %H:%M:%S') if hasattr(dt, 'strftime') else str(dt)[5:19].replace('-', '/')
                
                result.append({
                    'time':        time_str,
                    'src_ip':      str(r.get('src_ip', '')),
                    'dest_port':   r.get('dest_port', 0),
                    'attack_type': r.get('attack_type', 'unknown'),
                    'label':       ATTACK_LABELS.get(r.get('attack_type', ''), 'Bilinmeyen'),
                    'color':       ATTACK_COLORS.get(r.get('attack_type', ''), '#64748b'),
                    'severity':    r.get('severity', 3),
                    'signature':   (r.get('signature') or '')[:80],
                })
            return jsonify(result)
        except Exception as e:
            print(f"[DB HATA] api_alerts başarısız: {e}")
            pass
    return jsonify(list(alert_buffer))


@app.route('/api/timeline')
@login_required
def api_timeline():
    if DB_ENABLED:
        try:
            stats = get_alert_stats()
            return jsonify(stats.get('timeline', []))
        except Exception as e:
            app.logger.error(f"Timeline API Error: {e}")
    return jsonify(list(timeline))


@app.route('/api/unblock/<path:ip>', methods=['POST'])
@login_required
def api_unblock(ip):
    if not valid_ip(ip):
        return jsonify({'success': False, 'message': 'Geçersiz IP'}), 400
    remove_drop_rules(ip)
    if DB_ENABLED:
        try:
            save_unblock(ip)
        except Exception:
            pass
    state_path = '/var/log/netspecter/state.json'
    state = get_state()
    if ip in state.get('blocked_ips', {}):
        del state['blocked_ips'][ip]
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
    socketio.emit('blocked_update', get_blocked_ips())
    return jsonify({'success': True, 'ip': ip})


# ── Eve.json İzleyici ───────────────────────────────────────────────────

def watch_eve():
    eve_path = '/var/log/suricata/eve.json'

    while not os.path.exists(eve_path):
        time.sleep(2)

    with open(eve_path, 'r', errors='replace') as f:
        f.seek(0, 2)
        pos = f.tell()

    current_minute = None
    minute_count = 0

    while True:
        try:
            if not os.path.exists(eve_path):
                time.sleep(3)
                continue

            with open(eve_path, 'r', errors='replace') as f:
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

                if ev.get('event_type') != 'alert':
                    continue

                alert  = ev.get('alert', {})
                src_ip = ev.get('src_ip', '')
                sig    = alert.get('signature', '')
                cat    = alert.get('category', '')
                sev    = alert.get('severity', 3)

                if is_noisy(sig):
                    continue

                attack_type = classify(sig, cat, ev.get('dest_port', 0))

                alert_obj = {
                    'time':        datetime.now().strftime('%d/%m %H:%M:%S'),
                    'src_ip':      src_ip,
                    'dest_port':   ev.get('dest_port', 0),
                    'attack_type': attack_type,
                    'label':       ATTACK_LABELS.get(attack_type, 'Bilinmeyen'),
                    'color':       ATTACK_COLORS.get(attack_type, '#64748b'),
                    'severity':    sev,
                    'signature':   sig[:80],
                }
                alert_buffer.append(alert_obj)

                # Timeline bucket
                minute = datetime.now().strftime('%H:%M')
                if minute != current_minute:
                    if current_minute:
                        timeline.append({'time': current_minute, 'count': minute_count})
                    current_minute = minute
                    minute_count = 1
                else:
                    minute_count += 1

                # Socket.IO ile canlı gönder
                socketio.emit('new_alert', alert_obj)

            time.sleep(0.3)

        except Exception as e:
            time.sleep(2)


def watch_blocks():
    """State değişikliklerini izle ve engelleme güncellemelerini gönder"""
    last_mtime = 0
    last_count = -1
    state_path = '/var/log/netspecter/state.json'

    while True:
        try:
            if DB_ENABLED:
                blocks = get_active_blocks()
                current_count = len(blocks)
                if current_count != last_count:
                    last_count = current_count
                    socketio.emit('blocked_update', get_blocked_ips())
                    socketio.emit('stats_update', get_system_stats())
            else:
                if os.path.exists(state_path):
                    mtime = os.path.getmtime(state_path)
                    if mtime != last_mtime:
                        last_mtime = mtime
                        socketio.emit('blocked_update', get_blocked_ips())
                        socketio.emit('stats_update', get_system_stats())
        except Exception as e:
            pass
        time.sleep(2)


if __name__ == '__main__':
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("Root gerekli: sudo python3 dashboard.py")
        sys.exit(1)

    # Eski process'leri temizle (sadece Linux'ta)
    if sys.platform != 'win32':
        import signal
        current_pid = os.getpid()
        result = subprocess.run(['pgrep', '-f', 'dashboard.py'], capture_output=True, text=True)
        for pid_str in result.stdout.strip().splitlines():
            pid = int(pid_str)
            if pid != current_pid:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        time.sleep(1)

    # Veritabanını başlat
    if DB_ENABLED:
        try:
            init_db()
        except Exception as e:
            print(f'[DB] Başlatılamadı: {e}')

    # Arka plan thread'leri
    threading.Thread(target=watch_eve, daemon=True).start()
    threading.Thread(target=watch_blocks, daemon=True).start()

    print("""
╔══════════════════════════════════════════╗
║   NetSpecter Dashboard başlatılıyor...   ║
║   http://localhost:5000                  ║
║   http://<pi-ip>:5000                    ║
╚══════════════════════════════════════════╝
""")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)





