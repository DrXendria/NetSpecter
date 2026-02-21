#!/usr/bin/env python3
"""
NetSpecter — IDS/IPS Sistem Test Scripti
Kullanım: sudo python3 test_system.py
"""

import os, sys, json, time, subprocess

RED = '\033[0;31m'; GRN = '\033[0;32m'; YLW = '\033[1;33m'; BLU = '\033[1;34m'; NC = '\033[0m'
ok   = lambda s: print(f"{GRN}[✓]{NC} {s}")
fail = lambda s: print(f"{RED}[✗]{NC} {s}")
info = lambda s: print(f"{YLW}[*]{NC} {s}")
errors = 0

def run(cmd): return subprocess.run(cmd, capture_output=True, text=True)

def check(cond, msg_ok, msg_fail):
    global errors
    if cond: ok(msg_ok)
    else: fail(msg_fail); errors += 1

def ensure_chain():
    r = run(['iptables', '-L', 'IDS_IPS', '-n'])
    if r.returncode != 0:
        info("IDS_IPS zinciri yok, test için geçici kuruluyor...")
        run(['iptables', '-N', 'IDS_IPS'])
        run(['iptables', '-I', 'INPUT',   '1', '-j', 'IDS_IPS'])
        run(['iptables', '-I', 'FORWARD', '1', '-j', 'IDS_IPS'])
        run(['iptables', '-A', 'IDS_IPS', '-j', 'RETURN'])
        return True
    return False

def cleanup_chain():
    run(['iptables', '-D', 'INPUT',   '-j', 'IDS_IPS'])
    run(['iptables', '-D', 'FORWARD', '-j', 'IDS_IPS'])
    run(['iptables', '-F', 'IDS_IPS'])
    run(['iptables', '-X', 'IDS_IPS'])

print(f"\n{BLU}{'='*52}\n      NetSpecter IDS/IPS — Sistem Test Aracı\n{'='*52}{NC}\n")

# 1. Root
print("=== 1. Yetkiler ===")
check(os.geteuid() == 0, "Root yetkileri mevcut.", "Root gerekli! → sudo python3 test_system.py")
if os.geteuid() != 0: sys.exit(1)

# 2. Suricata
print("\n=== 2. Suricata ===")
r = run(['which', 'suricata'])
check(r.returncode == 0, f"Suricata kurulu: {r.stdout.strip()}", "Suricata bulunamadı! → sudo apt install suricata")
r = run(['suricata', '--build-info'])
check(r.returncode == 0, "Suricata build-info alındı.", "Suricata build-info okunamadı.")
conf = '/etc/suricata/suricata.yaml'
check(os.path.exists(conf), f"Config mevcut: {conf}", f"Config bulunamadı: {conf}")
if os.path.exists(conf):
    text = open(conf).read()
    check('eve-log' in text and 'eve.json' in text, "Eve.json config'de etkin.", "Eve.json config'de bulunamadı!")

# 3. iptables
print("\n=== 3. iptables ===")
check(run(['which', 'iptables']).returncode == 0, "iptables kurulu.", "iptables bulunamadı!")
we_made_chain = ensure_chain()
r = run(['iptables', '-L', 'IDS_IPS', '-n'])
msg = "IDS_IPS zinciri test için geçici kuruldu." if we_made_chain else "IDS_IPS zinciri mevcut (sistem çalışıyor)."
check(r.returncode == 0, msg, "IDS_IPS zinciri kurulamadı!")

# 4. Python modülleri
print("\n=== 4. Python modülleri ===")
sys.path.insert(0, '/opt/netspecter'); sys.path.insert(0, '.')
for mod in ['config', 'blocker', 'monitor', 'reporter']:
    try:
        if mod in sys.modules: del sys.modules[mod]
        __import__(mod); ok(f"  {mod}.py import OK")
    except ImportError as e:
        fail(f"  {mod}.py import HATA: {e}"); errors += 1

# 5. IPBlocker testi
print("\n=== 5. IPBlocker testi ===")
try:
    if 'blocker' in sys.modules: del sys.modules['blocker']
    from blocker import IPBlocker
    b = IPBlocker()
    TEST_IP = '10.255.255.1'
    result = b.block_ip(TEST_IP, 'NetSpecter test engeli', duration=10)
    check(result, f"block_ip({TEST_IP}) başarılı.", "block_ip başarısız!")
    time.sleep(0.3)
    r2 = run(['iptables', '-L', 'IDS_IPS', '-n'])
    check(TEST_IP in r2.stdout, f"iptables DROP kuralı mevcut: {TEST_IP}", f"iptables DROP kuralı bulunamadı!")
    result2 = b.unblock_ip(TEST_IP)
    check(result2, f"unblock_ip({TEST_IP}) başarılı.", "unblock_ip başarısız!")
    r3 = run(['iptables', '-L', 'IDS_IPS', '-n', '--line-numbers'])
    drop_gone = not any(
        TEST_IP in line and ('DROP' in line or 'LOG' in line)
        for line in r3.stdout.splitlines()
    )
    check(drop_gone, "Engel kaldırıldı, iptables temiz.", "Engel hâlâ iptables'da!")
except Exception as e:
    fail(f"IPBlocker exception: {e}"); import traceback; traceback.print_exc(); errors += 1

# 6. Monitor testi
print("\n=== 6. Monitor + Eve.json testi ===")
try:
    for m in ['blocker', 'monitor']:
        if m in sys.modules: del sys.modules[m]
    from blocker import IPBlocker
    from monitor import AlertMonitor
    TEST_EVE = '/tmp/netspecter_test_eve.json'
    TEST_SRC = '172.16.99.1'
    alert = {"timestamp":"2024-01-01T00:00:00+0000","event_type":"alert","src_ip":TEST_SRC,
             "src_port":54321,"dest_ip":"192.168.1.1","dest_port":80,"proto":"TCP",
             "alert":{"action":"allowed","gid":1,"signature_id":2009582,"rev":5,
                      "signature":"ET SCAN Nmap Scripting Engine User-Agent Detected",
                      "category":"Detection of a Network Scan","severity":2}}
    open(TEST_EVE,'w').write(json.dumps(alert)+'\n')
    b2 = IPBlocker(); m2 = AlertMonitor(b2)
    m2._process(open(TEST_EVE).readline().strip())
    check(b2.is_blocked(TEST_SRC), f"Nmap alert → {TEST_SRC} engellendi.", f"{TEST_SRC} engellenmedi!")
    b2.unblock_ip(TEST_SRC); os.remove(TEST_EVE)
except Exception as e:
    fail(f"Monitor exception: {e}"); import traceback; traceback.print_exc(); errors += 1

# 7. Servis
print("\n=== 7. Systemd servisi ===")
r = run(['systemctl', 'is-active', 'netspecter'])
if r.stdout.strip() == 'active': ok("netspecter servisi aktif çalışıyor.")
else: info("netspecter servisi henüz başlatılmamış.")

if we_made_chain:
    cleanup_chain()
    info("Test için kurulan geçici IDS_IPS zinciri temizlendi.")

print(f"\n{BLU}{'='*52}{NC}")
if errors == 0:
    print(f"{GRN}  ✓ Tüm testler geçti! NetSpecter hazır.{NC}\n")
    print("  sudo systemctl start netspecter")
    print("  sudo journalctl -u netspecter -f")
else:
    print(f"{RED}  ✗ {errors} test başarısız!{NC}")
print(f"{BLU}{'='*52}{NC}\n")
