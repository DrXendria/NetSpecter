#!/usr/bin/env python3
"""
NetSpecter Dashboard — Flask Backend
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

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
from flask_socketio import SocketIO, emit

sys.path.insert(0, '/opt/netspecter')
sys.path.insert(0, '.')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netspecter-dashboard-2024-secure'
app.config['SESSION_COOKIE_HTTPONLY'] = True

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

try:
    from database import (
        verify_user, get_active_blocks,
        save_unblock, init_db, change_password, change_username,
        get_whitelist, add_whitelist, remove_whitelist
    )
    DB_ENABLED = True
except ImportError:
    DB_ENABLED = False

DASHBOARD_USER = 'admin'
DASHBOARD_PASS = 'netspecter'

alert_buffer = deque(maxlen=200)
timeline     = deque(maxlen=60)

ATTACK_COLORS = {
    'nmap_scan':        '#f59e0b',
    'brute_force_ssh':  '#ef4444',
    'brute_force_ftp':  '#f97316',
    'brute_force_http': '#ec4899',
    'dos_attack':       '#a855f7',
    'exploit':          '#dc2626',
    'malware':          '#ff0000',
    'web_attack':       '#06b6d4',
    'info_leak':        '#64748b',
    'unknown':          '#334155',
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


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated


# ── Auth ─────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET'])
def login_page():
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    if DB_ENABLED:
        success = verify_user(username, password)
    else:
        success = (username == DASHBOARD_USER and password == DASHBOARD_PASS)

    if success:
        session['logged_in'] = True
        session['username']  = username
        return jsonify({'success': True})
    return jsonify({'success': False}), 401


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# ── Sayfalar ─────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


@app.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html')


# ── Settings API ──────────────────────────────────────────────────────────

@app.route('/api/settings/change-password', methods=['POST'])
@login_required
def api_change_password():
    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'Veritabanı aktif değil'}), 400
    data     = request.get_json()
    username = session.get('username', 'admin')
    old_pass = data.get('old_password', '')
    new_pass = data.get('new_password', '')
    if not new_pass or len(new_pass) < 6:
        return jsonify({'success': False, 'message': 'Şifre en az 6 karakter olmalı'})
    success, msg = change_password(username, old_pass, new_pass)
    return jsonify({'success': success, 'message': msg})


@app.route('/api/settings/change-username', methods=['POST'])
@login_required
def api_change_username():
    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'Veritabanı aktif değil'}), 400
    data         = request.get_json()
    old_username = session.get('username', 'admin')
    new_username = data.get('new_username', '').strip()
    password     = data.get('password', '')
    if not new_username:
        return jsonify({'success': False, 'message': 'Kullanıcı adı boş olamaz'})
    success, msg = change_username(old_username, new_username, password)
    if success:
        session['username'] = new_username
    return jsonify({'success': success, 'message': msg})


# ── Whitelist API ─────────────────────────────────────────────────────────

@app.route('/api/whitelist', methods=['GET'])
@login_required
def api_whitelist_get():
    if not DB_ENABLED:
        return jsonify([])
    try:
        wl = get_whitelist()
        return jsonify([dict(r) for r in wl])
    except Exception as e:
        return jsonify([])


@app.route('/api/whitelist', methods=['POST'])
@login_required
def api_whitelist_add():
    if not DB_ENABLED:
        return jsonify({'success': False, 'message': 'Veritabanı aktif değil'}), 400
    data = request.get_json()
    ip   = data.get('ip', '').strip()
    desc = data.get('description', '').strip()
    if not ip:
        return jsonify({'success': False, 'message': 'IP boş olamaz'})
    success = add_whitelist(ip, desc)
    if success:
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': "Bu IP zaten whitelist'te"})


@app.route('/api/whitelist/<ip>', methods=['DELETE'])
@login_required
def api_whitelist_remove(ip):
    if not DB_ENABLED:
        return jsonify({'success': False}), 400
    success = remove_whitelist(ip)
    return jsonify({'success': success})


# ── Data ─────────────────────────────────────────────────────────────────

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
            blocks = get_active_blocks()
            wl     = get_whitelist() if DB_ENABLED else []
            return {
                'blocked_count':   len(blocks),
                'whitelist_count': len(wl),
                'total_alerts':    len(alert_buffer),
            }
        except Exception:
            pass

    state   = get_state()
    blocked = state.get('blocked_ips', {})
    return {
        'blocked_count':   len(blocked),
        'whitelist_count': 0,
        'total_alerts':    len(alert_buffer),
    }


def get_blocked_ips():
    if DB_ENABLED:
        try:
            blocks = get_active_blocks()
            result = []
            for b in blocks:
                result.append({
                    'ip':     str(b['ip']),
                    'reason': (b.get('reason') or '')[:60],
                    'time':   str(b.get('blocked_at', ''))[:19],
                })
            return result
        except Exception:
            pass

    state   = get_state()
    blocked = state.get('blocked_ips', {})
    now     = time.time()
    result  = []
    for ip, info in blocked.items():
        result.append({
            'ip':     ip,
            'reason': info.get('reason', '')[:60],
            'time':   datetime.fromtimestamp(info.get('time', now)).strftime('%H:%M:%S'),
        })
    return result


# ── API ───────────────────────────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())


@app.route('/api/blocked')
@login_required
def api_blocked():
    return jsonify(get_blocked_ips())


@app.route('/api/alerts')
@login_required
def api_alerts():
    # Her zaman önce buffer'dan dön (canlı veri), DB yoksa da çalışır
    result = list(alert_buffer)
    return jsonify(result)


@app.route('/api/timeline')
@login_required
def api_timeline():
    return jsonify(list(timeline))


@app.route('/api/unblock/<ip>', methods=['POST'])
@login_required
def api_unblock(ip):
    subprocess.run(['iptables', '-D', 'IDS_IPS', '-s', ip, '-j', 'DROP'],    capture_output=True)
    subprocess.run(['iptables', '-D', 'IDS_IPS', '-s', ip, '-j', 'LOG',
                    '--log-prefix', f'NETSPECTER_BLOCK:{ip}: '],              capture_output=True)
    if DB_ENABLED:
        try:
            save_unblock(ip)
        except Exception:
            pass
    state = get_state()
    if ip in state.get('blocked_ips', {}):
        del state['blocked_ips'][ip]
        try:
            with open('/var/log/netspecter/state.json', 'w') as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass
    socketio.emit('blocked_update', get_blocked_ips())
    return jsonify({'success': True, 'ip': ip})


# ── Eve.json izleyici ─────────────────────────────────────────────────────

def classify_alert(signature, category):
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
    if 'scan' in cat_l:    return 'nmap_scan'
    if 'dos'  in cat_l:    return 'dos_attack'
    return 'unknown'


def watch_eve():
    eve_path = '/var/log/suricata/eve.json'
    while not os.path.exists(eve_path):
        time.sleep(2)

    with open(eve_path, 'r', errors='replace') as f:
        f.seek(0, 2)
        pos = f.tell()

    current_minute = None
    minute_count   = 0

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
                pos   = f.tell()

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

                attack_type = classify_alert(sig, cat)
                alert_obj   = {
                    'time':        datetime.now().strftime('%H:%M:%S'),
                    'src_ip':      src_ip,
                    'dest_port':   ev.get('dest_port', 0),
                    'attack_type': attack_type,
                    'label':       ATTACK_LABELS.get(attack_type, 'Bilinmeyen'),
                    'color':       ATTACK_COLORS.get(attack_type, '#64748b'),
                    'severity':    sev,
                    'signature':   sig[:80],
                }
                alert_buffer.append(alert_obj)

                minute = datetime.now().strftime('%H:%M')
                if minute != current_minute:
                    if current_minute:
                        timeline.append({'time': current_minute, 'count': minute_count})
                    current_minute = minute
                    minute_count   = 1
                else:
                    minute_count += 1

                socketio.emit('new_alert', alert_obj)

            time.sleep(0.3)

        except Exception:
            time.sleep(2)


def watch_blocks():
    state_path = '/var/log/netspecter/state.json'
    last_mtime = 0
    while True:
        try:
            if os.path.exists(state_path):
                mtime = os.path.getmtime(state_path)
                if mtime != last_mtime:
                    last_mtime = mtime
                    socketio.emit('blocked_update', get_blocked_ips())
                    socketio.emit('stats_update', get_system_stats())
        except Exception:
            pass
        time.sleep(1)


if __name__ == '__main__':
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("Root gerekli: sudo python3 dashboard.py")
        sys.exit(1)

    if sys.platform != 'win32':
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

    if DB_ENABLED:
        try:
            init_db()
            print('[DB] Veritabanı hazır.')
        except Exception as e:
            print(f'[DB] Başlatılamadı: {e}')

    threading.Thread(target=watch_eve,    daemon=True).start()
    threading.Thread(target=watch_blocks, daemon=True).start()

    print("""
╔══════════════════════════════════════════╗
║   NetSpecter Dashboard başlatılıyor...   ║
║   http://localhost:5000                  ║
║   http://<pi-ip>:5000                    ║
╚══════════════════════════════════════════╝
""")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
