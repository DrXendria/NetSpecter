#!/usr/bin/env python3
"""
NetSpecter Yönetim Aracı (CLI)
Kullanım: sudo netspecter-manager <komut>
Engel bilgileri MySQL'den okunur/yazılır; çalışan servis değişiklikleri
~10 saniye içinde (DB senkronizasyonu) otomatik olarak uygular.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '/opt/netspecter')
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blocker import CHAIN, valid_ip, add_drop_rules, remove_drop_rules  # noqa: E402


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _db():
    """database modülünü yükle; hata varsa anlaşılır mesajla çık."""
    try:
        import database
        return database
    except Exception as e:
        print(f"✗ Veritabanı modülü yüklenemedi: {e}")
        print("  MySQL çalışıyor mu?  →  sudo systemctl status mariadb")
        sys.exit(1)


def _require_ip(ip: str):
    if not valid_ip(ip):
        print(f"✗ Geçersiz IP adresi: {ip}")
        sys.exit(1)


# ── Komutlar ────────────────────────────────────────────────────────────

def cmd_list(_):
    db = _db()
    blocks = db.get_active_blocks()
    if not blocks:
        print("Şu an engellenmiş IP yok.")
        return

    now = time.time()
    print(f"\n{'#':<3} {'IP':<40} {'Kalıcı':<7} {'Kalan':<10} {'Engellenme':<20} {'Sebep'}")
    print("─" * 120)
    for i, b in enumerate(blocks, 1):
        permanent = bool(b.get('permanent', 1))
        expires   = b.get('expires_at')
        if permanent or expires is None:
            remaining = 'KALICI'
        else:
            remaining = f"{max(0, int(expires.timestamp() - now)) // 60} dk"
        blocked_at = b['blocked_at'].strftime('%d.%m.%Y %H:%M:%S')
        reason = (b.get('reason') or '')[:40]
        print(f"{i:<3} {b['ip']:<40} {'EVET' if permanent else 'Hayır':<7} "
              f"{remaining:<10} {blocked_at:<20} {reason}")
    print(f"\nToplam: {len(blocks)}")


def cmd_unblock(args):
    _require_ip(args.ip)
    db = _db()
    remove_drop_rules(args.ip)
    db.save_unblock(args.ip)
    print(f"✓ {args.ip} engeli kaldırıldı (iptables + veritabanı).")


def cmd_block(args):
    _require_ip(args.ip)
    db = _db()
    try:
        if args.ip in db.get_whitelist_ips():
            print(f"✗ {args.ip} whitelist'te, engellenmedi.")
            return
    except Exception:
        pass

    if not add_drop_rules(args.ip):
        print("✗ iptables kuralı eklenemedi.")
        return
    db.save_block(args.ip, f"manual | {args.reason}", 'manual',
                  permanent=args.permanent, duration=args.duration)
    label = 'KALICI' if args.permanent else f"{args.duration // 60} dk"
    print(f"✓ {args.ip} engellendi ({label}).")


def cmd_stats(_):
    db = _db()
    s = db.get_cli_stats()
    print("\n── NetSpecter İstatistikleri ───────────────")
    print(f"  Aktif engellenmiş IP  : {s['blocked_count']}")
    print(f"  Kalıcı engeller       : {s['permanent_count']}")
    try:
        a = db.get_alert_stats()
        print(f"  Son 24 saat alert     : {a['total']}")
        print(f"  Toplam alert          : {a['total_all']}")
        if a['dist']:
            print("\n  Son 24 saat saldırı dağılımı:")
            for t, c in sorted(a['dist'].items(), key=lambda x: -x[1]):
                print(f"    {str(t):<20} {c:>6}")
    except Exception:
        pass
    if s['top_violations']:
        print("\n  En çok engellenen IP'ler:")
        for ip, cnt in s['top_violations']:
            print(f"    {ip:<40} {cnt:>4} engel")


def cmd_iptables(_):
    for ipt in ('iptables', 'ip6tables'):
        r = _run([ipt, '-L', CHAIN, '-n', '-v', '--line-numbers'])
        print(f"── {ipt} ──")
        print(r.stdout or r.stderr)


def cmd_test(_):
    """Eve.json'a sahte bir nmap alert'i ekle"""
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
    print("  NetSpecter çalışıyorsa bu IP birkaç saniye içinde engellenmeli.")
    print(f"  Kaldırmak için: sudo netspecter-manager unblock {alert['src_ip']}")


def cmd_whitelist(_):
    try:
        from config import CONFIG
        print("Statik whitelist (config.py):")
        for ip in CONFIG['blocking']['whitelist']:
            print(f"  {ip}")
    except Exception as e:
        print(f"Config okunamadı: {e}")

    try:
        db = _db()
        rows = db.get_whitelist()
        print("\nDinamik whitelist (veritabanı / dashboard):")
        for r in rows:
            print(f"  {r['ip']:<40} {r.get('description') or ''}")
    except SystemExit:
        pass


def cmd_whitelist_add(args):
    _require_ip(args.ip)
    db = _db()
    if db.add_whitelist(args.ip, args.description):
        remove_drop_rules(args.ip)
        db.save_unblock(args.ip)
        print(f"✓ {args.ip} whitelist'e eklendi (varsa engeli kaldırıldı).")
    else:
        print(f"ℹ {args.ip} zaten whitelist'te.")


def cmd_whitelist_remove(args):
    db = _db()
    if db.remove_whitelist(args.ip):
        print(f"✓ {args.ip} whitelist'ten çıkarıldı.")
    else:
        print(f"ℹ {args.ip} whitelist'te bulunamadı.")


# ── argparse ────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("Root gerekli: sudo netspecter-manager ...")
        sys.exit(1)

    p = argparse.ArgumentParser(prog='netspecter-manager',
                                description='NetSpecter Yönetim Aracı')
    sub = p.add_subparsers(dest='cmd', required=True)

    sub.add_parser('list',      help='Engelli IP\'leri listele')
    sub.add_parser('stats',     help='İstatistikler')
    sub.add_parser('iptables',  help='iptables/ip6tables zincirini göster')
    sub.add_parser('test',      help='Test alert ekle')
    sub.add_parser('whitelist', help='Whitelist\'i göster')

    p_wl_add = sub.add_parser('whitelist-add', help='IP\'yi whitelist\'e ekle')
    p_wl_add.add_argument('ip')
    p_wl_add.add_argument('--description', default='CLI')

    p_wl_rm = sub.add_parser('whitelist-remove', help='IP\'yi whitelist\'ten çıkar')
    p_wl_rm.add_argument('ip')

    p_unblock = sub.add_parser('unblock', help='IP engelini kaldır')
    p_unblock.add_argument('ip')

    p_block = sub.add_parser('block', help='IP\'yi manuel engelle')
    p_block.add_argument('ip')
    p_block.add_argument('--reason', default='Manuel engel')
    p_block.add_argument('--permanent', action='store_true', help='Süresiz engel')
    p_block.add_argument('--duration', type=int, default=3600,
                         help='Süreli engelde süre (saniye, varsayılan 3600)')

    args = p.parse_args()
    {
        'list':             cmd_list,
        'unblock':          cmd_unblock,
        'block':            cmd_block,
        'stats':            cmd_stats,
        'iptables':         cmd_iptables,
        'test':             cmd_test,
        'whitelist':        cmd_whitelist,
        'whitelist-add':    cmd_whitelist_add,
        'whitelist-remove': cmd_whitelist_remove,
    }[args.cmd](args)


if __name__ == '__main__':
    main()
