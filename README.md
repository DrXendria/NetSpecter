# 🛡️ NetSpecter — IDS/IPS Sistemi v2.0

Raspberry Pi üzerinde çalışan, **Suricata + Python + iptables** tabanlı gerçek zamanlı saldırı tespit ve önleme sistemi. Web dashboard, Telegram bildirimleri ve canlı log izleme özelliklerine sahiptir.

---

## 📋 İçindekiler

- [Özellikler](#özellikler)
- [Sistem Mimarisi](#sistem-mimarisi)
- [Gereksinimler](#gereksinimler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Web Dashboard](#web-dashboard)
- [Telegram Bildirimleri](#telegram-bildirimleri)
- [Yapılandırma](#yapılandırma)
- [Dosya Yapısı](#dosya-yapısı)
- [Tespit Edilen Saldırılar](#tespit-edilen-saldırılar)

---

## ✨ Özellikler

- 🔍 **Gerçek zamanlı saldırı tespiti** — Suricata ile 48.000+ kural
- 🚫 **Otomatik IP engelleme** — iptables ile anında blok
- 📊 **Web dashboard** — canlı alert akışı, grafikler, engelli IP yönetimi
- 📱 **Telegram bildirimleri** — DDoS ve kritik alertlerde anlık mesaj
- 🖥️ **Tek komutla başlatma** — `sudo netspecter`
- 🔐 **Login koruması** — dashboard şifre ile korunur
- 🌐 **TR/EN dil desteği** — dashboard ve login sayfasında
- ♻️ **Otomatik kural güncelleme** — her 24 saatte bir
- 💾 **Kalıcı engel kaydı** — yeniden başlatmada engeller korunur

---

## 🏗️ Sistem Mimarisi

```
┌─────────────────────────────────────────────────────┐
│                   sudo netspecter                    │
└──────────┬──────────────┬──────────────┬────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌────▼────────┐
    │  NetSpecter │ │ Dashboard │ │  Telegram   │
    │   Servisi   │ │  :5000    │ │    Bot      │
    └──────┬──────┘ └─────┬─────┘ └────┬────────┘
           │              │             │
    ┌──────▼──────────────▼─────────────▼────────┐
    │              Suricata IDS Engine             │
    │           eve.json  ←  Ağ trafiği           │
    └──────────────────┬──────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────┐
    │               monitor.py                     │
    │         Alert sınıflandırma & eşik           │
    └──────────────────┬──────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────┐
    │               blocker.py                     │
    │          iptables IDS_IPS zinciri            │
    └─────────────────────────────────────────────┘
```

---

## 📦 Gereksinimler

- Raspberry Pi (herhangi bir model, Raspberry Pi OS)
- Python 3.9+
- Suricata 7.x
- iptables
- Flask, Flask-SocketIO, requests

---

## 🚀 Kurulum

### 1. Repoyu klonla

```bash
git clone https://github.com/kullanici/netspecter.git
cd netspecter
```

### 2. Ortam değişkenlerini ayarla

```bash
cp .env.example .env
nano .env
```

`.env` içeriği:
```env
TELEGRAM_BOT_TOKEN=buraya_bot_token
TELEGRAM_CHAT_ID=buraya_chat_id
```

### 3. Kurulum scriptini çalıştır

```bash
sudo bash install.sh
```

Script şunları otomatik yapar:
- Suricata kurulumu ve yapılandırması
- Python bağımlılıklarının kurulumu
- systemd servis kaydı
- iptables zinciri oluşturma
- `netspecter` ve `netspecter-manager` komutlarının eklenmesi

### 4. Whitelist'i yapılandır

```bash
sudo nano /opt/netspecter/config.py
```

Kendi IP adresinizi ekleyin:
```python
'whitelist': [
    '127.0.0.1',
    '::1',
    '192.168.1.x',  # Kendi IP'niz
],
```

### 5. Kurulumu test et

```bash
sudo python3 test_system.py
```

---

## 🖥️ Kullanım

### Sistemi başlat

```bash
sudo netspecter
```

Bu komut tek seferde şunları başlatır:
1. **NetSpecter IDS/IPS servisi**
2. **Web dashboard** (arka planda, port 5000)
3. **Telegram botu** (arka planda, `.env` varsa)
4. **Canlı log akışı** (terminalde)

Terminali kapatmak log izlemeyi durdurur, servisler arka planda çalışmaya devam eder.

### Servis yönetimi

```bash
sudo systemctl start   netspecter   # Başlat
sudo systemctl stop    netspecter   # Durdur
sudo systemctl restart netspecter   # Yeniden başlat
sudo systemctl status  netspecter   # Durum
```

### IP yönetimi

```bash
sudo netspecter-manager list               # Engelli IP'leri listele
sudo netspecter-manager stats              # İstatistikleri göster
sudo netspecter-manager block 192.168.1.x  # Manuel engelle
sudo netspecter-manager unblock 192.168.1.x # Engeli kaldır
sudo netspecter-manager test               # Test alert oluştur
```

---

## 🌐 Web Dashboard

Sistem başladıktan sonra tarayıcıdan erişin:

```
http://<raspberry-pi-ip>:5000
```



> ⚠️ Giriş bilgilerini değiştirmek için `dashboard.py` içindeki `DASHBOARD_USER` ve `DASHBOARD_PASS` değişkenlerini düzenleyin.

Dashboard şunları gösterir:
- Gerçek zamanlı alert akışı (Socket.IO)
- Saldırı tipi dağılımı (doughnut chart)
- Dakika bazlı alert zaman çizelgesi
- Engellenen IP listesi ve engel kaldırma
- Sistem istatistikleri

---

## 📱 Telegram Bildirimleri

### Bot kurulumu

1. Telegram'da `@BotFather`'a yaz → `/newbot` → token al
2. `@userinfobot`'a yaz → Chat ID al
3. `.env` dosyasına ekle:

```env
TELEGRAM_BOT_TOKEN=1234567890:ABCdef...
TELEGRAM_CHAT_ID=123456789
```

### Bildirim koşulları

| Durum | Açıklama |
|-------|----------|
| 🚨 DDoS | 60 sn içinde 10+ farklı IP'den saldırı |
| 🔴 Kritik | Severity = 1 alertler |
| 🟠 Yüksek | Severity = 2 alertler |

Aynı IP için 5 dakika boyunca tekrar bildirim gönderilmez.

---

## ⚙️ Yapılandırma

### `/opt/netspecter/config.py`

```python
CONFIG = {
    'suricata': {
        'interface': 'wlan0',               # Ağ arayüzü (eth0 veya wlan0)
    },
    'blocking': {
        'block_duration': 3600,             # Geçici engel süresi (saniye)
        'permanent_block_threshold': 5,     # Kalıcı engel için ihlal sayısı
        'whitelist': ['127.0.0.1', '::1'],
    },
}
```

### `/opt/netspecter/.env`

```env
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
DDOS_TIME_WINDOW=60       # DDoS zaman penceresi (saniye)
DDOS_MIN_IPS=10           # DDoS eşiği (farklı IP sayısı)
NOTIFY_COOLDOWN=300       # Bildirim tekrar süresi (saniye)
```

---

## 📁 Dosya Yapısı

```
netspecter/
├── ids_ips.py           # Ana orkestratör, Suricata yönetimi
├── blocker.py           # iptables IP engelleme motoru
├── monitor.py           # eve.json alert işleyici
├── config.py            # Merkezi yapılandırma
├── reporter.py          # JSON rapor üretici
├── manager.py           # CLI yönetim aracı
├── netspecter_cli.py    # sudo netspecter komutu
├── dashboard.py         # Flask web dashboard backend
├── telegram_bot.py      # Telegram bildirim botu
├── test_system.py       # Otomatik kurulum doğrulama
├── install.sh           # Kurulum scripti
├── .env.example         # Ortam değişkenleri şablonu
├── .gitignore
└── templates/
    ├── dashboard.html   # Dashboard arayüzü
    └── login.html       # Giriş sayfası
```

---

## 🎯 Tespit Edilen Saldırılar

| Saldırı Tipi | Örnekler | Engel Süresi |
|---|---|---|
| Port Tarama | nmap -sS, -sV, -O | 1 saat |
| SSH Brute Force | Hydra, Medusa | 2 saat |
| FTP Brute Force | Hydra, Medusa | 2 saat |
| HTTP Brute Force | Hydra, Nikto, dirb | 2 saat |
| DoS/DDoS | SYN flood, UDP flood | 24 saat |
| Exploit | SQLi, XSS, RCE, LFI | Kalıcı |
| Malware/Trojan | C2 iletişimi, botnet | Kalıcı |
| Web Saldırısı | sqlmap, nikto | 2 saat |

---

## 🔒 Güvenlik Notları

- `.env` dosyasını asla GitHub'a göndermeyin (`.gitignore` ile korunur)
- Dashboard giriş bilgilerini varsayılan değerden değiştirin
- Kendi IP adresinizi whitelist'e eklemeyi unutmayın
- Dashboard'a yalnızca yerel ağdan erişilmesi önerilir

---

## 📄 Lisans

Bu proje bir mezuniyet tezi kapsamında geliştirilmiştir.
