#!/bin/bash
# ============================================================
# NetSpecter IDS/IPS Kurulum Scripti v2
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[*]${NC} $1"; }

[[ $EUID -ne 0 ]] && err "Root gerekli: sudo bash install.sh"

echo "============================================================"
echo "       NetSpecter IDS/IPS Kurulumu v2"
echo "============================================================"

# ── 1. Paketler ────────────────────────────────────────────────────────
info "Paketler kuruluyor..."
apt-get update -qq
apt-get install -y suricata suricata-update iptables python3 \
    net-tools iproute2 -qq
ok "Paketler hazır."

# ── 2. Dizinler ────────────────────────────────────────────────────────
info "Dizinler oluşturuluyor..."
mkdir -p /opt/netspecter /var/log/netspecter/reports /var/log/suricata
ok "Dizinler hazır."

# ── 3. Dosyalar ────────────────────────────────────────────────────────
info "Dosyalar kopyalanıyor..."
cp ids_ips.py blocker.py monitor.py reporter.py config.py manager.py /opt/netspecter/
chmod +x /opt/netspecter/ids_ips.py /opt/netspecter/manager.py
ok "Dosyalar: /opt/netspecter/"

# ── 4. Arayüz tespiti ──────────────────────────────────────────────────
IFACE=$(ip route show default 2>/dev/null | awk '/dev/{print $5}' | head -1)
[[ -z "$IFACE" ]] && IFACE="eth0"
info "Tespit edilen arayüz: $IFACE"
sed -i "s/_detect_interface()/'$IFACE'  # auto-detected/" \
    /opt/netspecter/config.py 2>/dev/null || true

# ── 5. Suricata eve.json yapılandırması ───────────────────────────────
info "Suricata eve.json ayarlanıyor..."
SCONF="/etc/suricata/suricata.yaml"

# Python ile yaml'ı güvenli şekilde patch et
python3 << 'PYEOF'
import re, sys

path = "/etc/suricata/suricata.yaml"
try:
    text = open(path).read()
except FileNotFoundError:
    print("suricata.yaml bulunamadı, atlanıyor.")
    sys.exit(0)

# eve-log bloğunu etkinleştir
# Yoruma alınmış "- eve-log:" satırını aç
text = re.sub(r'#\s*(-\s*eve-log:)', r'\1', text)

# filename: /var/log/suricata/eve.json satırını garantile
if 'eve.json' not in text:
    # outputs bölümüne ekle
    text = text.replace(
        'outputs:',
        'outputs:\n  - eve-log:\n      enabled: yes\n'
        '      filename: /var/log/suricata/eve.json\n'
        '      types:\n        - alert\n        - anomaly\n'
        '        - flow\n'
    )

open(path, 'w').write(text)
print("suricata.yaml güncellendi.")
PYEOF

ok "Suricata eve.json etkin."

# ── 6. Suricata kuralları ──────────────────────────────────────────────
info "Suricata kuralları indiriliyor (internet gerekli)..."
suricata-update 2>&1 | tail -3 || info "Kural güncellemesi başarısız (internet yoksa normal)"
ok "Kurallar güncellendi."

# ── 7. Suricata testi ─────────────────────────────────────────────────
info "Suricata config doğrulanıyor..."
suricata -T -c "$SCONF" -i "$IFACE" 2>&1 | tail -5
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    info "Config testi uyarı verdi, lütfen kontrol edin: $SCONF"
else
    ok "Suricata config geçerli."
fi

# ── 8. Systemd servisi ────────────────────────────────────────────────
info "Systemd servisi kuruluyor..."
cat > /etc/systemd/system/netspecter.service << EOF
[Unit]
Description=NetSpecter IDS/IPS System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netspecter
ExecStart=/usr/bin/python3 /opt/netspecter/ids_ips.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netspecter.service
ok "Systemd servisi etkin."

# ── 9. netspecter-manager komutu ─────────────────────────────────────────────
cat > /usr/local/bin/netspecter-manager << 'EOF'
#!/bin/bash
exec python3 /opt/netspecter/manager.py "$@"
EOF
chmod +x /usr/local/bin/netspecter-manager
ok "netspecter-manager komutu kuruldu."

# ── 10. Logrotate ─────────────────────────────────────────────────────
cat > /etc/logrotate.d/netspecter << 'EOF'
/var/log/netspecter/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
EOF
ok "Logrotate ayarlandı."

# ── Özet ──────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "${GREEN}  Kurulum tamamlandı!${NC}"
echo "============================================================"
echo ""
echo "  Arayüz  : $IFACE"
echo "  Eve log  : /var/log/suricata/eve.json"
echo "  IDS log  : /var/log/netspecter/system.log"
echo ""
echo "  ÖNEMLİ: config.py dosyasını açın ve whitelist'e"
echo "  kendi IP adresinizi ekleyin, yoksa kendinizi de"
echo "  engelleyebilirsiniz!"
echo ""
echo "  nano /opt/netspecter/config.py"
echo ""
echo "  Başlatmak için:"
echo "    sudo systemctl start netspecter"
echo "    sudo journalctl -u netspecter -f"
echo ""
echo "  Yönetim:"
echo "    sudo netspecter-manager list"
echo "    sudo netspecter-manager stats"
echo "    sudo netspecter-manager test      ← sistemi test et"
echo "    sudo netspecter-manager unblock <ip>"
echo "============================================================"
