#!/usr/bin/env python3
"""
NetSpecter Dashboard — Flask Backend
Kullanım: sudo python3 dashboard.py
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from collections import deque
from pathlib import Path

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
from flask_socketio import SocketIO, emit

sys.path.insert(0, '/opt/netspecter')
sys.path.insert(0, '.')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netspecter-dashboard-2024-secure'
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Giriş bilgileri — değiştirmeniz önerilir
DASHBOARD_USER = 'admin'
DASHBOARD_PASS = 'netspecter'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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
    data = request.get_json()
    if (data.get('username') == DASHBOARD_USER and
            data.get('password') == DASHBOARD_PASS):
        session['logged_in'] = True
        return jsonify({'success': True})
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
    state = get_state()
    blocked = state.get('blocked_ips', {})
    violations = state.get('violation_counts', {})

    # Saldırı tipi dağılımı
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
        'top_attackers':   sorted(violations.items(), key=lambda x: -x[1])[:5],
    }


def get_blocked_ips():
    state = get_state()
    blocked = state.get('blocked_ips', {})
    now = time.time()
    result = []
    for ip, info in blocked.items():
        if info.get('permanent'):
            remaining = '∞ Kalıcı'
        else:
            secs = int(info.get('duration', 3600) - (now - info.get('time', now)))
            mins = max(0, secs // 60)
            remaining = f'{mins} dk'
        result.append({
            'ip':        ip,
            'reason':    info.get('reason', '')[:60],
            'permanent': info.get('permanent', False),
            'remaining': remaining,
            'count':     info.get('count', 1),
            'time':      datetime.fromtimestamp(
                info.get('time', now)).strftime('%H:%M:%S'),
        })
    return sorted(result, key=lambda x: x['count'], reverse=True)


# ── API Endpointleri ────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')


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
    return jsonify(list(alert_buffer))


@app.route('/api/timeline')
@login_required
def api_timeline():
    return jsonify(list(timeline))


@app.route('/api/unblock/<ip>', methods=['POST'])
@login_required
def api_unblock(ip):
    import subprocess
    subprocess.run(['iptables', '-D', 'IDS_IPS', '-s', ip, '-j', 'DROP'],
                   capture_output=True)
    subprocess.run(['iptables', '-D', 'IDS_IPS', '-s', ip, '-j', 'LOG',
                    '--log-prefix', f'NETSPECTER_BLOCK:{ip}: '],
                   capture_output=True)
    state = get_state()
    if ip in state.get('blocked_ips', {}):
        del state['blocked_ips'][ip]
        with open('/var/log/netspecter/state.json', 'w') as f:
            json.dump(state, f, indent=2)
    socketio.emit('blocked_update', get_blocked_ips())
    return jsonify({'success': True, 'ip': ip})


# ── Eve.json İzleyici ───────────────────────────────────────────────────

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
    if 'scan' in cat_l:
        return 'nmap_scan'
    if 'dos' in cat_l or 'denial' in cat_l:
        return 'dos_attack'
    return 'unknown'


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

                attack_type = classify_alert(sig, cat)

                alert_obj = {
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
    if os.geteuid() != 0:
        print("Root gerekli: sudo python3 dashboard.py")
        sys.exit(1)

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
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
