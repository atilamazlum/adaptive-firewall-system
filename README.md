# 3LayerFirewall — IDS/IPS Güvenlik Sistemi

Bitirme projesi. Gerçek zamanlı saldırı tespiti ve engelleme sistemi.

---

## Proje Yapısı
```
3layerfirewall/          ← Ana güvenlik motoru
├── main.py              ← Giriş noktası
├── engine.py            ← Layer 1-2-3 zinciri
├── log_parser.py        ← Log analizi (Layer 1)
├── risk_scorer.py       ← IP puanlama (Layer 2)
├── nftables.py          ← Engelleme (Layer 3)
├── geoip.py             ← Ülke tespiti
├── banner.py            ← Terminal arayüzü
└── config.py            ← Merkezi ayarlar

target-site/             ← Hedef web sitesi
├── server.js            ← Node.js backend
└── public/index.html    ← Login sayfası
```

---

## 3 Katman Nasıl Çalışır?
```
Saldırı → Layer 1 (Tespit) → Layer 2 (Puanlama) → Layer 3 (Ban)
```

**Layer 1 — Tespit**
Log dosyasını okur. Brute force, port tarama, DDoS, HTTP anomali pattern'lerini regex ile tespit eder.

**Layer 2 — Puanlama**
Tespit edilen olayları 0-100 arası puanlar. Sadece istek sayısı değil:
- Hız (10 saniyede kaç istek?)
- Gece saati mi? (00:00-05:00 arası +%25)
- Karma saldırı mı? (birden fazla tür +15 puan)
- Yabancı ülke mi? (GeoIP ile +20 puan)
- Süreklilik (5 dakika+ devam ediyorsa +10 puan)

**Layer 3 — Engelleme**
Puan 70'i geçince nftables'a gider, IP gerçekten engellenir. 1 saat sonra otomatik kalkar.

---

## Kurulum
```bash
# nftables kur
python3 main.py --setup

# Bağımlılıklar (GeoIP için internet yeterli, ek paket yok)
python3 --version  # 3.8+ olmalı
```

---

## Çalıştırma
```bash
# Simülasyon modu (test için, sahte saldırılar)
python3 main.py --simulate

# Canlı mod (gerçek auth.log izleme)
sudo python3 main.py

# Hedef siteyi izleme
sudo python3 main.py --log-path ~/target-site/access.log

# Dry-run (ban yok, sadece göster)
python3 main.py --dry-run
```

---

## İki Çalışma Modu

### Mod 1 — Öylece Test (Simülasyon)

V1 kendi kendine sahte saldırı logları üretir ve tespit eder.
İnternet bağlantısı gerekmez, gerçek bir hedef site gerekmez.
```
python3 main.py --simulate
```
```
[03:14:22] [BRUTE] 185.220.101.45   🇺🇸 US/Ashburn   skor= 85 ████████████░░░ brute_force=6
╔══════════════════════════════════════════╗
║  🚫  BAN KARARI VERİLDİ — LAYER 3 AKTİF ║
║  IP    : 185.220.101.45                  ║
║  Konum : 🇺🇸 US / Ashburn               ║
║  Skor  : 85/100                          ║
╚══════════════════════════════════════════╝
```

### Mod 2 — Gerçek Hedef Site ile Entegrasyon

Target-site çalışırken 3LayerFirewall o siteyi izler.
Gerçek HTTP trafiği → log → tespit → ban.

**Terminal 1 — Hedef siteyi başlat:**
```bash
cd ~/target-site
node server.js
# → http://localhost:3000
```

**Terminal 2 — Firewall'u başlat:**
```bash
cd ~/3layerfirewall
sudo python3 main.py --log-path ~/target-site/access.log
```

**Akış:**
```
Kullanıcı yanlış şifre girer
        ↓
target-site/access.log'a yazar
        ↓
3LayerFirewall log'u okur
        ↓
Layer 1: brute_force tespit eder
        ↓
Layer 2: skor hesaplar (GeoIP dahil)
        ↓
Layer 3: nftables ile IP'yi engeller
        ↓
Kullanıcı siteye erişemez
```

---

## nftables Komutları
```bash
# Banlı IP'leri gör
nft list set inet filter banned_ips

# Tüm kuralları gör
nft list ruleset

# Manuel ban ekle
nft add element inet filter banned_ips { 1.2.3.4 }

# IP'yi unban et
nft delete element inet filter banned_ips { 1.2.3.4 }

# Hepsini temizle
nft flush set inet filter banned_ips

# Greylist'e ekle (izle ama banlama)
nft add element inet filter graylisted_ips { 1.2.3.4 }

# Whitelist'e ekle (asla banlanmaz)
nft add element inet filter whitelisted_ips { 1.2.3.4 }
```

---

## Risk Skoru Tablosu

| Kriter | Puan |
|--------|------|
| Brute force eşiği aşıldı | +30-50 |
| Port tarama eşiği aşıldı | +30-50 |
| DDoS eşiği aşıldı | +30-50 |
| Yüksek hız (10s içinde 20+ istek) | +30 max |
| Gece saati (00:00-05:00) | +%25 |
| Karma saldırı (2+ tür) | +15 |
| Yabancı ülke (GeoIP) | +20 |
| Süreklilik (5 dk+) | +10 |
| **Ban eşiği** | **70** |
| **Maksimum** | **100** |

---

## Eşik Değerleri (config.py)
```python
THRESHOLDS = {
    "brute_force":  {"count": 5,   "window": 60},   # 60s içinde 5 fail
    "port_scan":    {"count": 10,  "window": 30},   # 30s içinde 10 port
    "ddos":         {"count": 100, "window": 10},   # 10s içinde 100 istek
    "http_anomaly": {"count": 20,  "window": 60},   # 60s içinde 20 anomali
}
BAN_SCORE_THRESHOLD = 70
BAN_DURATION = 3600  # 1 saat
```
