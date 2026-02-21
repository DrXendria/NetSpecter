# 🛡️ NetSpecter — IDS/IPS Sistemi v2

NetSpecter; Suricata + Python + iptables tabanlı, **gerçekten çalışan** IDS/IPS sistemi.

---

## ⚡ Kurulum (3 adım)

```bash
# 1. Dosyaları Raspberry Pi'ye kopyalayın, dizine girin
cd ids_ips_v2/

# 2. Kurulum scriptini çalıştırın
sudo bash install.sh

# 3. Kendi IP'nizi whitelist'e ekleyin (ÇOK ÖNEMLİ!)
sudo nano /opt/netspecter/config.py
# 'whitelist' listesine '192.168.1.x' şeklinde kendi IP'nizi yazın

# 4. Başlatın
sudo systemctl start netspecter
sudo journalctl -u netspecter -f
```

---

## ✅ Her Şey Çalışıyor mu? Test Edin

```bash
sudo python3 test_system.py
```

Bu script sırasıyla şunları test eder:
- Root yetkisi ✓
- Suricata kurulu ve config geçerli ✓
- Eve.json etkin ✓
- iptables IDS_IPS zinciri kurulu ✓
- Python modülleri import edilebilir ✓
- Gerçek bir nmap alert'i parse edip IP'yi engelliyor ✓
- Systemd servisi durumu ✓

---

## 🔍 Nmap Taramasını Test Etme

```bash
# Başka bir makineden (veya telefondan):
nmap -sS -p 1-1000 <raspberry_pi_ip>

# Pi üzerinde logları izleyin:
sudo journalctl -u netspecter -f

# Beklenen çıktı:
# [ALERT] 192.168.x.x → port 80 | nmap_scan | sev=2 | ET SCAN Nmap...
# [ENGELLENDİ] 192.168.x.x | nmap_scan | ... | Süre: 60 dk | İhlal #1
```

---

## 📁 Dosya Yapısı

| Dosya | Görev |
|---|---|
| `ids_ips.py` | Ana program — Suricata'yı başlatır, thread'leri yönetir |
| `blocker.py` | iptables motoru — güvenli zincir kurulumu ve IP engelleme |
| `monitor.py` | Eve.json tail — saldırı sınıflandırma ve aksiyon |
| `reporter.py` | JSON rapor üretici |
| `config.py` | Tüm ayarlar |
| `manager.py` | CLI yönetim aracı |
| `install.sh` | Otomatik kurulum |
| `test_system.py` | Uçtan uca sistem testi |

---

## 🐛 v1'den Düzeltilen Hatalar

1. **Suricata daemon sorunu** — `-D` flag'i kaldırıldı, Suricata artık doğrudan subprocess olarak yönetiliyor. Çöktüğünde watchdog otomatik yeniden başlatıyor.

2. **iptables zincir çakışması** — Zincir oluşturmadan önce INPUT/FORWARD yönlendirmeleri kaldırılıyor, sonra zincir sıfırlanıp yeniden kuruluyor.

3. **Eve.json race condition** — Dosya boyut kontrolü eklendi (logrotate sonrası başa dön), `errors='replace'` ile encoding hatası önlendi.

4. **Suricata başlamadan "başarılı" dönmesi** — Eve.json oluşana kadar bekleme döngüsü eklendi, process poll() kontrolü yapılıyor.

5. **Modüler config** — Arayüz otomatik tespit ediliyor, whitelist config.py'de merkezi olarak yönetiliyor.

---

## ⚙️ Önemli Ayarlar (config.py)

```python
# Kendi IP'nizi whitelist'e ekleyin!
'whitelist': ['127.0.0.1', '::1', '192.168.1.100'],

# IPS (engeller) veya IDS (sadece loglar) modu
'enabled': True,

# Engelleme süreleri (saniye)
# nmap_scan   → 3600  (1 saat)
# brute_force → 7200  (2 saat)
# dos_attack  → 86400 (24 saat)
# malware     → 604800 (1 hafta, kalıcı)
```

---

## 🖥️ Yönetim Komutları

```bash
sudo netspecter-manager list              # Engelli IP'leri göster
sudo netspecter-manager stats             # İstatistikler
sudo netspecter-manager unblock 1.2.3.4   # Engel kaldır
sudo netspecter-manager block 1.2.3.4     # Manuel engel
sudo netspecter-manager iptables          # iptables kurallarını göster
sudo netspecter-manager test              # Sahte nmap alert ekle
```

---

## 🔧 Sorun Giderme

```bash
# Suricata config testi
sudo suricata -T -c /etc/suricata/suricata.yaml

# Eve.json canlı izleme
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool

# iptables zincirini sıfırla
sudo iptables -F IDS_IPS
sudo iptables -D INPUT -j IDS_IPS 2>/dev/null
sudo iptables -D FORWARD -j IDS_IPS 2>/dev/null
sudo iptables -X IDS_IPS

# Sistem logları
sudo journalctl -u netspecter -f --no-pager
```
