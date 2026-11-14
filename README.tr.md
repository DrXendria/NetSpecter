# 🛡️ NetSpecter — Raspberry Pi için Hafif IDS/IPS Sistemi

[English](README.md) | **Türkçe**

NetSpecter, Raspberry Pi (ve Debian/Ubuntu tabanlı tüm Linux sistemler) için geliştirilmiş gerçek zamanlı bir **Saldırı Tespit ve Önleme Sistemidir (IDS/IPS)**. **Suricata** tespit motorunu, uyarıları sınıflandıran ve saldırganları **iptables / ip6tables** ile otomatik olarak engelleyen Python tabanlı bir karar katmanıyla birleştirir. Tüm olaylar **MySQL / MariaDB** veritabanına kaydedilir; canlı **web dashboard**, renkli **terminal olay akışı**, **Telegram bildirimleri** ve indirilebilir **PDF raporları** üzerinden sunulur.

> Bu proje bir mezuniyet tezi kapsamında geliştirilmiştir.

---

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Sistem Mimarisi ve Çalışma Akışı](#-sistem-mimarisi-ve-çalışma-akışı)
- [Gereksinimler](#-gereksinimler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Web Dashboard](#-web-dashboard)
- [Telegram Bildirimleri](#-telegram-bildirimleri)
- [PDF ve JSON Raporları](#-pdf-ve-json-raporları)
- [Yapılandırma](#-yapılandırma)
- [Tespit Edilen Saldırılar ve Kurallar](#-tespit-edilen-saldırılar-ve-kurallar)
- [Veritabanı Şeması](#-veritabanı-şeması)
- [Dosya Yapısı](#-dosya-yapısı)
- [Test](#-test)
- [Sorun Giderme](#-sorun-giderme)
- [Güvenlik Notları](#-güvenlik-notları)
- [Lisans](#-lisans)

---

## ✨ Özellikler

| | Özellik | Açıklama |
|---|---|---|
| 🔍 | **Gerçek zamanlı tespit** | Suricata ve Emerging Threats kural seti (48.000+ kural) ile canlı ağ trafiği analizi |
| 🧠 | **Birleşik sınıflandırma** | İmzalar, kategoriler ve portlar 9 saldırı sınıfına (`nmap_scan`, `brute_force_*`, `dos_attack`, `exploit`, `malware`, `web_attack`, `info_leak`) ayrılır |
| 🚫 | **IPv4 & IPv6 otomatik engelleme** | Saldırgan IP'ler özel `IDS_IPS` zincirinde (`iptables` + `ip6tables`) mükerrer kural korumasıyla anında bloklanır |
| ⏱️ | **Eşik ve süre mantığı** | Brute-force saldırılarında yanlış pozitifleri önlemek için zaman penceresi eşiği; manuel kaldırmaya kadar kalıcı veya süreli engel seçeneği |
| 🧾 | **Protokol anomalisi engelleme** | Suricata `applayer`, `decode` ve `stream` anomalilerinde otomatik bloklama |
| 🛡️ | **İki katmanlı Whitelist** | `config.py` içinde statik liste + MySQL tabanlı dinamik liste (Dashboard ve CLI üzerinden yönetilebilir) |
| 💾 | **Kalıcı durum (MySQL)** | Tüm alertler, engeller ve whitelist kayıtları MariaDB/MySQL'de tutulur; sistem yeniden başladığında aktif engeller iptables'a geri yüklenir |
| 📊 | **Canlı Web Dashboard** | Flask + Socket.IO: anlık alert akışı, saldırı dağılım grafiği, 24 saatlik zaman çizelgesi, tek tıkla engel kaldırma ve whitelist yönetimi |
| 🔐 | **Güçlendirilmiş kimlik doğrulama** | Tuzlanmış `PBKDF2-HMAC-SHA256` (200.000 iterasyon) şifre özeti, brute-force hız sınırı, `HttpOnly`/`SameSite=Lax` oturum çerezleri |
| 🌐 | **TR / EN dil desteği** | Giriş ekranı ve dashboard üzerinde anlık Türkçe / İngilizce dil geçişi |
| 📱 | **Telegram botu** | Kritik/yüksek önemdeki alertlerde (`sev 1–2`) ve koordineli DDoS saldırılarında anlık bildirim |
| 📄 | **PDF & JSON raporlama** | Tek tıkla günlük güvenlik özeti PDF'i, IP bazlı adli analiz PDF raporu ve saatlik JSON özetleri |
| 🖥️ | **Tek komutla başlatma** | `sudo netspecter` komutu servisi, dashboard'u ve botu başlatıp canlı renkli log akışını açar |
| ♻️ | **Otomatik bakım** | 24 saatte bir kural güncelleme (`SIGUSR2`), Suricata watchdog, 10 saniyede bir DB senkronizasyonu ve logrotate |

---

## 🏗️ Sistem Mimarisi ve Çalışma Akışı

```
                         ┌────────────────────────┐
                         │     sudo netspecter    │  (netspecter_cli.py)
                         └───┬─────────┬────────┬─┘
                             │         │        │
              systemd servis │         │        │ arka plan süreçleri
                             ▼         ▼        ▼
┌───────────────────────────────┐ ┌──────────┐ ┌──────────────┐
│ ids_ips.py  (orkestratör)     │ │dashboard │ │ telegram_bot │
│  ├─ Suricata başlat & izle    │ │  .py     │ │     .py      │
│  ├─ monitor.py  (sınıflandır) │ │ :5000    │ │              │
│  ├─ blocker.py  (ip[6]tables) │ └────┬─────┘ └──────┬───────┘
│  └─ periyodik görev & DB sync │      │              │
└──────┬─────────────────┬──────┘      │              │
       │ tail            │ oku/yaz     │ tail + O/Y   │ tail
       ▼                 ▼             ▼              ▼
┌──────────────────┐  ┌───────────────────────┐  ┌──────────────────┐
│ Suricata         │  │ MySQL  (netspecter)   │  │ Telegram Bot API │
│ eve.json         │  │ alerts / blocked_ips  │  └──────────────────┘
│ ← ağ trafiği     │  │ whitelist / users     │
└──────────────────┘  └───────────────────────┘
       │
       ▼
iptables / ip6tables  INPUT & FORWARD ──► IDS_IPS zinciri ──► LOG + DROP <saldırgan-ip>
```

---

## 📦 Gereksinimler

- Raspberry Pi 3 / 4 / 5 (veya Debian / Ubuntu tabanlı herhangi bir Linux sistem)
- Raspberry Pi OS / Debian 12+ veya Ubuntu 22.04+
- Root yetkisi (`sudo`)
- Python 3.10+, Suricata 7.x, iptables, MariaDB/MySQL (`install.sh` tamamını otomatik kurar)

---

## 🚀 Kurulum

### 1. Repoyu klonlayın

```bash
git clone https://github.com/DrXendria/NetSpecter.git
cd NetSpecter
```

### 2. Ortam değişkenlerini hazırlayın (isteğe bağlı)

```bash
cp .env.example .env
nano .env
```

`TELEGRAM_BOT_TOKEN` ve `TELEGRAM_CHAT_ID` değerlerini girin. Veritabanı ve dashboard şifrelerini boş veya `CHANGE_ME` bırakırsanız `install.sh` otomatik olarak güçlü rastgele şifreler üretip `/opt/netspecter/.env` dosyasına yazar.

### 3. Kurulum scriptini çalıştırın

```bash
sudo bash install.sh
```

Script şunları otomatik olarak yapar:
- `suricata`, `suricata-update`, `iptables`, `mariadb-server`, derleme araçları ve `fonts-dejavu-core` paketlerini kurar
- Tüm proje dosyalarını **`/opt/netspecter/`** dizinine kopyalar (`.env` izinlerini `600` yapar)
- Varsayılan ağ arayüzünü (`eth0` / `wlan0`) tespit edip `/opt/netspecter/config.py` içine yazar
- `/etc/suricata/suricata.yaml` içinde `eve.json` çıktısını etkinleştirir ve kuralları indirir
- Python paketlerini (`flask`, `flask-socketio`, `requests`, `mysqlclient`, `reportlab`) kurar
- MariaDB veritabanını, kullanıcıyı ve tabloları (`database.py`) oluşturur
- `netspecter.service` systemd servisini, `netspecter` ve `netspecter-manager` komutlarını kurar

> [!IMPORTANT]
> Kurulum sonunda üretilen **Dashboard `admin` şifresi** ekrana yazdırılır ve `/opt/netspecter/.env` içinde `DASHBOARD_ADMIN_PASSWORD` anahtarına kaydedilir.

### 4. Kendi IP adresinizi Whitelist'e ekleyin ⚠️

```bash
sudo netspecter-manager whitelist-add 192.168.1.10 --description "Yönetim Bilgisayarım"
```

### 5. Kurulumu test edin

```bash
cd /opt/netspecter
sudo python3 test_system.py
```

---

## 🖥️ Kullanım

### Tek komutla başlatma

```bash
sudo netspecter
```

Bu komut sırasıyla:
1. NetSpecter systemd servisini başlatır,
2. Web Dashboard'u arka planda başlatır (`:5000`),
3. Telegram botunu arka planda başlatır (`.env` yapılandırılmışsa),
4. Terminalde canlı ve renkli olay akışını açar (`Ctrl+C` ile çıkıldığında servisler arka planda çalışmaya devam eder).

### Servis yönetimi

```bash
sudo systemctl start   netspecter
sudo systemctl stop    netspecter
sudo systemctl restart netspecter
sudo systemctl status  netspecter
sudo journalctl -u netspecter -f
```

### Yönetim CLI (`netspecter-manager`)

```bash
sudo netspecter-manager list                                              # Aktif engelli IP'leri listele
sudo netspecter-manager stats                                             # İstatistikleri göster
sudo netspecter-manager iptables                                          # IDS_IPS zincirini göster (v4 & v6)
sudo netspecter-manager block 203.0.113.5 --reason "Manuel" --permanent   # Kalıcı manuel engel
sudo netspecter-manager block 203.0.113.5 --duration 3600                 # Süreli manuel engel (saniye)
sudo netspecter-manager unblock 203.0.113.5                               # Engeli kaldır (iptables + DB)
sudo netspecter-manager whitelist                                         # Statik ve DB whitelist'i göster
sudo netspecter-manager whitelist-add 192.168.1.10 --description "Admin"  # DB whitelist'e ekle
sudo netspecter-manager whitelist-remove 192.168.1.10                     # DB whitelist'ten çıkar
sudo netspecter-manager test                                              # eve.json'a test Nmap alert'i ekle
```

---

## 🌐 Web Dashboard

Tarayıcıdan erişin:

```
http://<raspberry-pi-ip>:5000
```

- **Giriş:** `admin` ve kurulum sonunda verilen şifre (`/opt/netspecter/.env` → `DASHBOARD_ADMIN_PASSWORD`).
- **Ayarlar (`/settings`):** Kullanıcı adı ve şifrenizi istediğiniz zaman değiştirebilirsiniz.
- **Özellikler:** Canlı Socket.IO alert akışı, saldırı tipi dağılım grafiği, 24 saatlik zaman çizelgesi, tek tıkla IP engeli kaldırma, dinamik Whitelist yönetimi, günlük ve IP bazlı PDF rapor indirme, TR/EN dil seçimi.

---

## 📱 Telegram Bildirimleri

1. Telegram'da `@BotFather` → `/newbot` ile token alın.
2. `@userinfobot` ile Chat ID'nizi öğrenin.
3. `/opt/netspecter/.env` dosyasına `TELEGRAM_BOT_TOKEN` ve `TELEGRAM_CHAT_ID` değerlerini ekleyin.

| Durum | Koşul |
|---|---|
| 🚨 **Olası DDoS** | `DDOS_TIME_WINDOW` (varsayılan 60 sn) içinde `DDOS_MIN_IPS` (varsayılan 10+) farklı IP'den aynı tipte saldırı |
| 🔴 **Kritik** | Severity = 1 alertler |
| 🟠 **Yüksek** | Severity = 2 alertler |

Aynı IP için `NOTIFY_COOLDOWN` (varsayılan 300 sn) boyunca tekrar bildirim gönderilmez.

---

## 📄 PDF ve JSON Raporları

Raporlar `/var/log/netspecter/reports/` dizinine kaydedilir ve Dashboard üzerinden indirilebilir:
- **Günlük Güvenlik Özeti (PDF):** Son 24 saatteki toplam alert, yeni engellenen IP sayısı ve en çok saldıran ilk 5 IP (`/api/report/daily`).
- **IP Saldırı Analiz Raporu (PDF):** Seçilen IP'nin toplam saldırı/engel sayısı ve son 40 saldırı girişiminin detayı (`/api/report/ip/<ip>`).
- **Periyodik Rapor (JSON):** Saatlik ve kapanış anındaki sistem istatistikleri.

---

## ⚙️ Yapılandırma (`/opt/netspecter/config.py`)

```python
CONFIG = {
    'suricata': {
        'config_path': '/etc/suricata/suricata.yaml',
        'eve_log':     '/var/log/suricata/eve.json',
        'log_dir':     '/var/log/suricata',
        'interface':   'wlan0',   # install.sh otomatik tespit eder
    },
    'blocking': {
        'enabled': True,                        # False → sadece IDS (loglama) modu
        'block_duration': 3600,                 # Varsayılan geçici engel süresi (sn)
        'permanent_block_threshold': 5,         # 5 ihlal → kalıcı engel
        'persist_until_manual_unblock': True,   # True → tüm engeller manuel kaldırılana dek kalıcı
        'whitelist': ['127.0.0.1', '::1'],
    },
}
```

---

## 🎯 Tespit Edilen Saldırılar ve Kurallar

| Sınıf | Örnek Araçlar / İmzalar | Aksiyon | Eşik | Tanımlı Süre* |
|---|---|---|---|---|
| `brute_force_ssh` | SSH tarama/brute, Hydra, Medusa | Engelle | 3 alert / 60 sn | 2 saat |
| `brute_force_ftp` | FTP brute/login hatası, anonim FTP | Engelle | 3 alert / 60 sn | 2 saat |
| `brute_force_http` | HTTP/Web brute, credential stuffing, Hydra | Engelle | 5 alert / 60 sn | 1 saat |
| `malware` | `ET MALWARE`, `ET TROJAN`, C2, botnet, ransomware | Engelle | Anında | Kalıcı |
| `exploit` | `ET EXPLOIT`, RCE, `CVE-*`, SQLi, Command Injection, Path Traversal, LFI/RFI, SSRF, XXE | Engelle | Anında | 24 saat |
| `dos_attack` | `ET DOS`, SYN/UDP/ICMP/HTTP flood | Engelle | Anında | 24 saat |
| `web_attack` | `ET WEB_SERVER`, XSS, CSRF, web shell, Nikto, sqlmap, gobuster, ffuf, wpscan, Burp, ZAP | Engelle | Anında | 1 saat |
| `nmap_scan` | `ET SCAN`, Nmap, Masscan, ZMap, SYN/NULL/XMAS/FIN taramaları | Engelle | Anında | 1 saat |
| `info_leak` | `ET INFO`, `ET HUNTING`, `ET POLICY`, keşif | Logla** | — | — |
| Protokol anomalisi | Suricata `applayer`, `decode`, `stream` anomalileri | Engelle | Anında | 30 dakika |

\* `persist_until_manual_unblock: True` (varsayılan) iken tüm engeller Dashboard veya CLI üzerinden kaldırılana kadar aktif kalır. Süreli engelleri kullanmak için `False` yapabilirsiniz.  
\** Suricata `severity <= 2` olan tüm uyarılar sınıfı ne olursa olsun engellenir.

---

## 🗄️ Veritabanı Şeması

| Tablo | Açıklama |
|---|---|
| `users` | Dashboard kullanıcıları (`pbkdf2_sha256` şifre özeti ve salt) |
| `alerts` | Sınıflandırılmış tüm Suricata uyarıları |
| `blocked_ips` | Aktif ve geçmiş IP engelleri (`permanent`, `expires_at`, `blocked_at`, `unblocked_at`) |
| `whitelist` | Dinamik beyaz liste IP kayıtları |
| `ddos_events` | Tespit edilen DDoS olayları |

---

## 📁 Dosya Yapısı

```
NetSpecter/
├── ids_ips.py          # Ana orkestratör, Suricata yönetimi, watchdog ve periyodik görevler
├── monitor.py          # eve.json okuyucu, birleşik saldırı sınıflandırıcı ve eşik kontrolü
├── blocker.py          # iptables / ip6tables IDS_IPS zincir motoru ve DB senkronizasyonu
├── database.py         # MySQL/MariaDB katmanı, şema/migration ve PBKDF2 kimlik doğrulama
├── config.py           # Merkezi yapılandırma
├── dashboard.py        # Flask + Socket.IO web dashboard backend
├── telegram_bot.py     # Telegram bildirim ve DDoS tespit botu
├── reporter.py         # PDF (günlük / IP bazlı) ve JSON rapor üretici
├── netspecter_cli.py   # `sudo netspecter` başlatıcı ve canlı renkli olay akışı
├── manager.py          # `sudo netspecter-manager` CLI yönetim aracı
├── test_system.py      # Otomatik kurulum ve bileşen doğrulama testi
├── install.sh          # Otomatik kurulum scripti
├── .env.example        # Ortam değişkenleri şablonu
├── LICENSE             # MIT Lisansı
├── README.md           # İngilizce dokümantasyon
├── README.tr.md        # Türkçe dokümantasyon
└── templates/
    ├── dashboard.html  # Dashboard arayüzü (TR / EN)
    ├── login.html      # Giriş sayfası (TR / EN)
    └── settings.html   # Hesap ayarları sayfası
```

---

## 🧪 Test

```bash
sudo python3 /opt/netspecter/test_system.py   # Otomatik sistem testi
sudo netspecter-manager test                  # Sahte Nmap alert'i ile uçtan uca test
```

---

## 🩺 Sorun Giderme

| Sorun | Çözüm |
|---|---|
| Hiç alert gelmiyor | `/opt/netspecter/config.py` içindeki `interface` değerini `ip route show default` ile kontrol edin |
| Kendinizi engellediniz | Pi konsolundan `sudo iptables -F IDS_IPS` ve `sudo netspecter-manager whitelist-add <ip>` çalıştırın |
| Veritabanı hatası | `sudo systemctl status mariadb` ve `/opt/netspecter/.env` içindeki `DB_*` ayarlarını kontrol edin |
| PDF'te Türkçe karakter sorunu | `sudo apt install -y fonts-dejavu-core` paketini kurun |

---

## 🔒 Güvenlik Notları

- **`.env` dosyasını asla GitHub'a göndermeyin:** Daha önce git geçmişine girdiyse `git rm --cached .env` ile takipten çıkarın ve Telegram Bot Token (`@BotFather` → `/revoke`) ile veritabanı şifrenizi yenileyin.
- Testlere başlamadan önce kendi yönetim IP adresinizi mutlaka whitelist'e ekleyin.
- Dashboard'a yalnızca yerel ağdan (veya VPN / HTTPS ters vekil sunucu üzerinden) erişilmesi önerilir.

---

## 📄 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakabilirsiniz.
