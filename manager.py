#!/usr/bin/env python3
"""
NetSpecter Yönetim Aracı (CLI)
Kullanım: sudo python3 manager.py <komut>
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime


STATE_FILE = '/var/log/netspecter/state.json'
CHAIN      = 'IDS_IPS'


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        print("State dosyası bulunamadı. Sistem çalışıyor mu?")
        return None
    except Exception as e:
        print(f"State okunamadı: {e}")
        return None


def _save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


# ── Komutlar ────────────────────────────────────────────────────────────

def cmd_list(_):
    state = _load_state()
    if state is None:
        return

    blocked = state.get('blocked_ips', {})
    if not blocked:
        print("Şu an engellenmiş IP yok.")
        return

    now = datetime.now().timestamp()
    print(f"\n{'#':<3} {'IP':<18} {'Kalıcı':<8} {'Kalan':<12} {'Sebep'}")
    print("─" * 85)
    for i, (ip, info) in enumerate(blocked.items(), 1):
        permanent = info.get('permanent', False)
        if permanent:
            remaining = 'KALICI'
        else:
            secs = int(info.get('duration', 3600) - (now - info.get('time', now)))
            remaining = f"{max(0, secs // 60)} dk"
        reason = info.get('reason', '')[:45]
        print(f"{i:<3} {ip:<18} {'EVET' if permanent else 'Hayır':<8} {remaining:<12} {reason}")
    print(f"\nToplam: {len(blocked)}")


def cmd_unblock(args):
    ip = args.ip
    r = _run(['iptables', '-D', CHAIN, '-s', ip, '-j', 'DROP'])
    _run(['iptables', '-D', CHAIN, '-s', ip, '-j', 'LOG', '--log-prefix', f'IDS_BLOCK:{ip}: '])

    state = _load_state()
    if state and ip in state.get('blocked_ips', {}):
        del state['blocked_ips'][ip]
        _save_state(state)
        print(f"✓ {ip} engeli kaldırıldı.")
    else:
        print(f"✓ iptables kuralı kaldırıldı (state'de yoktu): {ip}")


def cmd_block(args):
    ip     = args.ip
    reason = args.reason
    r = _run(['iptables', '-I', CHAIN, '1', '-s', ip, '-j', 'DROP'])
    if r.returncode == 0:
        state = _load_state() or {'blocked_ips': {}, 'violation_counts': {}}
        import time
        state['blocked_ips'][ip] = {
            'time': time.time(), 'reason': reason,
            'permanent': args.permanent, 'duration': 3600,
        }
        _save_state(state)
        print(f"✓ {ip} engellendi{'  (KALICI)' if args.permanent else ''}.")
    else:
        print(f"✗ iptables hatası: {r.stderr}")


def cmd_stats(_):
    state = _load_state()
    if state is None:
        return
    blocked    = state.get('blocked_ips', {})
    violations = state.get('violation_counts', {})
    print(f"\n── IDS/IPS İstatistikleri ──────────────────")
    print(f"  Toplam engellenmiş IP : {len(blocked)}")
    print(f"  Kalıcı engeller       : {sum(1 for i in blocked.values() if i.get('permanent'))}")
    if violations:
        print(f"\n  En çok ihlal eden IP'ler:")
        top = sorted(violations.items(), key=lambda x: -x[1])[:10]
        for ip, cnt in top:
            tag = '[ENGELLİ]' if ip in blocked else ''
            print(f"    {ip:<20} {cnt:>4} ihlal  {tag}")


def cmd_iptables(_):
    r = _run(['iptables', '-L', CHAIN, '-n', '-v', '--line-numbers'])
    print(r.stdout or r.stderr)


def cmd_test(_):
    """Eve.json'a sahte bir nmap alert'i ekle"""
    import json, time as _time
    alert = {
        "timestamp":  datetime.now().isoformat() + "+0000",
        "event_type": "alert",
        "src_ip":     "192.168.100.200",
        "src_port":   54321,
        "dest_ip":    "192.168.1.1",
        "dest_port":  80,
        "proto":      "TCP",
        "alert": {
            "action":       "allowed",
            "gid":          1,
            "signature_id": 2009582,
            "rev":          5,
            "signature":    "ET SCAN Nmap Scripting Engine User-Agent Detected",
            "category":     "Detection of a Network Scan",
            "severity":     2
        }
    }
    eve = '/var/log/suricata/eve.json'
    os.makedirs(os.path.dirname(eve), exist_ok=True)
    with open(eve, 'a') as f:
        f.write(json.dumps(alert) + '\n')
    print(f"✓ Test alert eklendi → {eve}")
    print(f"  src_ip    : {alert['src_ip']}")
    print(f"  signature : {alert['alert']['signature']}")
    print("  IDS/IPS çalışıyorsa bu IP birkaç saniye içinde engellenmeli.")


def cmd_whitelist(args):
    """config.py whitelist'ini göster (düzenleme için dosyayı açın)"""
    try:
        sys.path.insert(0, '/opt/netspecter')
        from config import CONFIG
        print("Mevcut whitelist:")
        for ip in CONFIG['blocking']['whitelist']:
            print(f"  {ip}")
        print("\nDüzenlemek için: nano /opt/netspecter/config.py")
    except Exception as e:
        print(f"Config okunamadı: {e}")


# ── argparse ────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("Root gerekli: sudo python3 manager.py ...")
        sys.exit(1)

    p = argparse.ArgumentParser(prog='netspecter-manager',
                                description='NetSpecter Yönetim Aracı')
    sub = p.add_subparsers(dest='cmd', required=True)

    sub.add_parser('list',      help='Engelli IP\'leri listele')
    sub.add_parser('stats',     help='İstatistikler')
    sub.add_parser('iptables',  help='iptables zincirini göster')
    sub.add_parser('test',      help='Test alert ekle')
    sub.add_parser('whitelist', help='Whitelist\'i göster')

    p_unblock = sub.add_parser('unblock', help='IP engelini kaldır')
    p_unblock.add_argument('ip')

    p_block = sub.add_parser('block', help='IP\'yi manuel engelle')
    p_block.add_argument('ip')
    p_block.add_argument('--reason', default='Manuel engel')
    p_block.add_argument('--permanent', action='store_true')

    args = p.parse_args()
    {
        'list':      cmd_list,
        'unblock':   cmd_unblock,
        'block':     cmd_block,
        'stats':     cmd_stats,
        'iptables':  cmd_iptables,
        'test':      cmd_test,
        'whitelist': cmd_whitelist,
    }[args.cmd](args)


if __name__ == '__main__':
    main()
