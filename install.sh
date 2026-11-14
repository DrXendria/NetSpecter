#!/bin/bash
# ============================================================
# NetSpecter IDS/IPS Kurulum Scripti v2.1
# ============================================================
set -e
 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[*]${NC} $1"; }
 
[[ $EUID -ne 0 ]] && err "Root gerekli: sudo bash install.sh"
 
echo "============================================================"
echo "       NetSpecter IDS/IPS Kurulumu v2.1"
echo "============================================================"
 
# ── 1. Paketler ────────────────────────────────────────────────────────
info "Paketler kuruluyor..."
apt-get update -qq
apt-get install -y -qq suricata suricata-update iptables python3 python3-pip \
    net-tools iproute2 mariadb-server python3-dev default-libmysqlclient-dev \
    build-essential pkg-config fonts-dejavu-core
ok "Paketler hazır."
 
# ── 2. Dizinler ────────────────────────────────────────────────────────
info "Dizinler oluşturuluyor..."
mkdir -p /opt/netspecter /var/log/netspecter/reports /var/log/suricata
ok "Dizinler hazır."
 
# ── 3. Dosyalar ────────────────────────────────────────────────────────
info "Dosyalar kopyalanıyor..."
cp ids_ips.py blocker.py monitor.py reporter.py config.py manager.py \
   database.py netspecter_cli.py test_system.py /opt/netspecter/
[[ -f dashboard.py ]]     && cp dashboard.py /opt/netspecter/
[[ -f telegram_bot.py ]]  && cp telegram_bot.py /opt/netspecter/
[[ -f .env.example ]]     && cp .env.example /opt/netspecter/
[[ -d templates ]] && { mkdir -p /opt/netspecter/templates; cp templates/*.html /opt/netspecter/templates/; }

# .env: kaynakta varsa onu kullan, yoksa mevcut olanı koru, o da yoksa şablondan oluştur
ENV_FILE=/opt/netspecter/.env
if [[ -f .env ]]; then
    cp .env "$ENV_FILE"
elif [[ ! -f "$ENV_FILE" && -f .env.example ]]; then
    cp .env.example "$ENV_FILE"
fi
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
chmod +x /opt/netspecter/ids_ips.py /opt/netspecter/manager.py
ok "Dosyalar: /opt/netspecter/"

# .env yardımcıları
get_env() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r'; }
set_env() {
    if grep -qE "^$1=" "$ENV_FILE"; then
        sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else
        echo "$1=$2" >> "$ENV_FILE"
    fi
}

# ── 4. Arayüz tespiti ──────────────────────────────────────────────────
IFACE=$(ip route show default 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[[ -z "$IFACE" ]] && IFACE="eth0"
info "Tespit edilen arayüz: $IFACE"
sed -i -E "s/('interface':[[:space:]]*)'[^']*'/\1'$IFACE'/" /opt/netspecter/config.py
ok "config.py → interface = $IFACE"

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
After=network.target mariadb.service mysql.service
Wants=mariadb.service
 
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
 
# ── 9. netspecter ve netspecter-manager komutları ────────────────────────────
cat > /usr/local/bin/netspecter << 'EOF'
#!/bin/bash
exec python3 /opt/netspecter/netspecter_cli.py "$@"
EOF
chmod +x /usr/local/bin/netspecter
ok "netspecter komutu kuruldu."
 
cat > /usr/local/bin/netspecter-manager << 'EOF'
#!/bin/bash
exec python3 /opt/netspecter/manager.py "$@"
EOF
chmod +x /usr/local/bin/netspecter-manager
ok "netspecter-manager komutu kuruldu."
 
# Python bağımlılıkları
info "Python bağımlılıkları kuruluyor..."
pip3 install flask flask-socketio requests mysqlclient reportlab --break-system-packages -q
ok "Python bağımlılıkları hazır."

# ── MySQL / MariaDB ───────────────────────────────────────────────────
info "Veritabanı hazırlanıyor..."
systemctl enable --now mariadb >/dev/null 2>&1 || systemctl enable --now mysql >/dev/null 2>&1 || true

DB_NAME=$(get_env DB_NAME); DB_NAME=${DB_NAME:-netspecter}
DB_USER=$(get_env DB_USER); DB_USER=${DB_USER:-netspecter}
DB_PASSWORD=$(get_env DB_PASSWORD)
if [[ -z "$DB_PASSWORD" || "$DB_PASSWORD" == "CHANGE_ME" || "$DB_PASSWORD" == "netspecter" ]]; then
    DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    info "Rastgele veritabanı şifresi üretildi (.env'e yazıldı)."
fi
set_env DB_HOST "$(get_env DB_HOST | grep . || echo localhost)"
set_env DB_PORT "$(get_env DB_PORT | grep . || echo 3306)"
set_env DB_NAME "$DB_NAME"
set_env DB_USER "$DB_USER"
set_env DB_PASSWORD "$DB_PASSWORD"

SQL_PASS=${DB_PASSWORD//\'/\'\'}
mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$SQL_PASS';
ALTER USER '$DB_USER'@'localhost' IDENTIFIED BY '$SQL_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL

# Dashboard admin şifresi
NEW_ADMIN_PASS=""
if [[ -z "$(get_env DASHBOARD_ADMIN_PASSWORD)" ]]; then
    NEW_ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(12))")
    set_env DASHBOARD_ADMIN_PASSWORD "$NEW_ADMIN_PASS"
fi

( cd /opt/netspecter && python3 database.py ) || info "Veritabanı başlatma uyarı verdi, lütfen kontrol edin."
ok "Veritabanı hazır: $DB_NAME"
 
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
echo "  Dashboard: http://<bu-cihazin-ip>:5000"
if [[ -n "$NEW_ADMIN_PASS" ]]; then
echo ""
echo "  Dashboard girişi:  admin / $NEW_ADMIN_PASS"
echo "  (Şifre /opt/netspecter/.env içinde DASHBOARD_ADMIN_PASSWORD olarak saklanır."
echo "   Dashboard → Ayarlar sayfasından değiştirebilirsiniz.)"
fi
echo ""
echo "  ÖNEMLİ: config.py dosyasını açın ve whitelist'e"
echo "  kendi IP adresinizi ekleyin, yoksa kendinizi de"
echo "  engelleyebilirsiniz!"
echo ""
echo "  nano /opt/netspecter/config.py"
echo ""
echo "  Başlatmak için:"
echo "    sudo netspecter"
echo ""
echo "  Yönetim:"
echo "    sudo netspecter-manager list"
echo "    sudo netspecter-manager stats"
echo "    sudo netspecter-manager test      ← sistemi test et"
echo "    sudo netspecter-manager unblock <ip>"
echo "============================================================"

