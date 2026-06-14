<div align="center">

# Adaptive Firewall System

**Üç Katmanlı Gerçek Zamanlı Saldırı Tespit ve Otomatik Engelleme Sistemi**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat-square)](https://nodejs.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=flat-square)](https://www.mysql.com/)
[![nftables](https://img.shields.io/badge/nftables-active-CC0000?style=flat-square)](https://netfilter.org/projects/nftables/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

*On farklı saldırı türünü gerçek zamanlı tespit eden, çok sinyalli risk puanlamasıyla karar veren ve nftables üzerinden çekirdek seviyesinde IP engelleyen modüler bir Linux güvenlik duvarı sistemi.*

</div>

---

## Genel Bakış

Bu sistem, sunucu altyapısına yönelik otomatik siber saldırıları gerçek zamanlı tespit eder, çok sinyalli bir algoritmayla risk skorunu hesaplar ve eşiği aşan IP'leri işletim sistemi seviyesinde otomatik engeller. Geleneksel araçların tek boyutlu eşik yaklaşımının ötesine geçerek saldırı türü, hızı, coğrafi kaynağı, saati ve çeşitliliğini bir arada değerlendirir.

Risk parametrelerinin tamamı yönetici tarafından dashboard üzerinden dinamik olarak yapılandırılabilir. Sistem statik kural setiyle değil, yöneticinin güvenlik politikasına göre ayarlanan parametrik bir karar mekanizmasıyla çalışır.

---

## Yetenekler

- On farklı saldırı türünün gerçek zamanlı tespiti
- Üç katmanlı işleme: Tespit → Puanlama → Engelleme
- Çok sinyalli risk algoritması (olay türü, hız, coğrafi köken, saat, çeşitlilik)
- Tüm parametreler dashboard üzerinden ayarlanabilir
- IPv4 ve IPv6 ortak desteği
- Kalıcı ban — yeniden başlatma sonrası otomatik geri yükleme
- WebSocket üzerinden gerçek zamanlı yönetim paneli
- Otomatik PDF rapor üretimi
- Telegram bot ile uzaktan komut desteği
- Honeypot tuzakları ile otomatik tarayıcı tespiti
- Saldırı simülatörü ile yeniden üretilebilir test
- GitHub Actions ile sürekli entegrasyon

---

## Mimari

```
                         DIŞ DÜNYA
              İnternet · Saldırganlar · Botlar
                            │
                            │  HTTPS (ngrok)
                            ▼
        ┌───────────────────────────────────────────┐
        │      HEDEF SİTE — Atila Bank :3000        │
        │   Node.js + Express · Olay logla & ban    │
        └────────┬──────────────────────┬───────────┘
                 │ access.log            │ ban check
                 ▼                       ▼
        ┌─────────────────────┐   ┌──────────────────────┐
        │  GÜVENLİK MOTORU    │   │   MySQL 8.0          │
        │                     │   │                      │
        │   Layer 1: Detect   │◄──┤   • banned_ips       │
        │   Layer 2: Score    │   │   • events           │
        │   Layer 3: Block    │──►│   • ip_profiles      │
        │                     │   │                      │
        │   + Telegram Bot    │   └──────────┬───────────┘
        └─────────┬───────────┘              │ WebSocket
                  │                          ▼
                  │ nftables           ┌──────────────────┐
                  ▼                    │ DASHBOARD :4000  │
        ┌──────────────────┐           │ Canlı izleme +   │
        │  Linux Kernel    │           │ PDF rapor +      │
        │    nftables      │           │ Konfigürasyon    │
        └──────────────────┘           └──────────────────┘
```

> Detaylı diyagramlar (ER, akış, UML) `docs/` klasöründedir.

---

## Tespit Edilen Saldırı Türleri

| Saldırı | Risk Puanı | Tehlike | Tespit Yöntemi |
|---------|:---:|:---:|---|
| Brute Force | 10 | Orta | Tekrar eden LOGIN_FAIL log girdileri |
| Slow Brute Force | 10 | Orta-Yüksek | Uzun pencerede biriken denemeler |
| Port Tarama | 10 | Düşük | Aynı IP'den farklı portlara erişim |
| Kötü Amaçlı Bot | 25 | Yüksek | User-Agent imzası (sqlmap, nmap) |
| DDoS / Flood | 25 | Yüksek | Kısa pencerede yüksek istek hızı |
| Çapraz Site Betikleme | 25 | Yüksek | Script ve handler desenleri |
| SQL Enjeksiyonu | 25 | Çok Yüksek | UNION SELECT, OR 1=1, SLEEP() |
| Dizin Geçişi | 25 | Yüksek | "../" ve URL kodlu varyantları |
| Komut Enjeksiyonu | 35 | Kritik | Shell metakarakter ve süreç ikamesi |
| Honeypot | 100 | Kesin | Tuzak yollara erişim |

Ban eşiği varsayılan olarak **70 puan**. Tüm puan ve eşik değerleri dashboard üzerinden değiştirilebilir.

---

## Kurulum

### Sistem Gereksinimleri

```bash
sudo apt update
sudo apt install -y python3 python3-pip nodejs npm mysql-server nftables

pip3 install mysql-connector-python requests

cd site && npm install && cd ..
cd dashboard && npm install && cd ..
```

### Veritabanı

```bash
sudo mysql -e "CREATE DATABASE firewall;
               CREATE USER 'fwuser'@'localhost' IDENTIFIED BY 'firewall123';
               GRANT ALL ON firewall.* TO 'fwuser'@'localhost';"

mysql -u fwuser -pfirewall123 firewall < schema.sql
```

### Telegram Bot (İsteğe Bağlı)

Proje kök dizininde `.telegram` dosyası oluşturun:

```
TOKEN=your_bot_token
CHAT_ID=your_chat_id
```

---

## Kullanım

### Tek Komutla Başlat

```bash
sudo bash start.sh
```

Üç servis ayağa kalkar:

| Servis | Adres |
|--------|-------|
| Hedef site | `http://localhost:3000` |
| Yönetim paneli | `http://localhost:4000` |
| Güvenlik motoru | Arka planda |

### Saldırı Simülatörü

```bash
python3 simulator/attack_sim.py --all
```

On farklı saldırı senaryosu otomatik olarak yeniden üretilir. Dashboard üzerinden gerçek zamanlı izleyebilirsiniz.

### Telegram Komutları

```
/stats             Sistem durumu özeti
/banlist           Aktif banlı IP'lerin listesi
/ban  1.2.3.4      Manuel IP engelleme
/unban 1.2.3.4     Ban kaldırma
/help              Komut yardımı
```

### Sistemi Durdur

```bash
bash stop.sh
```

---

## Proje Yapısı

```
adaptive-firewall-system/
│
├── main.py                 Giriş noktası
├── start.sh / stop.sh      Servis yönetim betikleri
├── schema.sql              MySQL veritabanı şeması
│
├── core/                   Güvenlik motoru (Python)
│   ├── engine.py             Üç katmanın orkestratörü
│   ├── detector.py           Layer 1 — regex tabanlı tespit
│   ├── scorer.py             Layer 2 — çok sinyalli puanlama
│   ├── blocker.py            Layer 3 — nftables engelleme
│   ├── geoip.py              Coğrafi sorgulama
│   ├── database.py           MySQL erişim katmanı
│   ├── telegram_bot.py       Telegram entegrasyonu
│   └── config.py             Varsayılan ayarlar
│
├── site/                   Hedef site — Atila Bank
│   ├── server.js             Express + olay loglama
│   └── public/               Banka arayüzü
│
├── dashboard/              Yönetim paneli
│   ├── server.js             Express + WebSocket + PDF
│   └── public/               Dashboard arayüzü
│
├── simulator/
│   └── attack_sim.py         Saldırı senaryoları
│
├── docs/                   Diyagramlar ve görseller
│   ├── er_diagram.png
│   ├── architecture.png
│   ├── workflow.png
│   ├── uml.png
│   ├── atilabank.png
│   └── dashboard.png
│
└── .github/workflows/ci.yml   Sürekli entegrasyon hattı
```

---

## Teknoloji Yığını

| Bileşen | Seçim | Gerekçe |
|---------|-------|---------|
| Güvenlik motoru | Python 3.12 | Regex olgunluğu, hızlı prototipleme |
| Site ve panel | Node.js + Express | Olay tabanlı I/O, WebSocket desteği |
| Veritabanı | MySQL 8.0 | Çoklu süreçten eşzamanlı erişim |
| Engelleme | nftables | Modern Linux çekirdek standardı |
| Canlı iletişim | WebSocket (ws) | Düşük gecikme, çoklu istemci |
| PDF üretimi | pdfkit | Programatik vektör çizim |
| Coğrafi IP | ip-api.com | Ücretsiz, kurulum gerektirmez |
| CI/CD | GitHub Actions | Otomatik test ve kontrol |

---

## Örnek Saldırı Akışı

```
1.  Saldırgan         →  Atila Bank :3000     [SQL injection denemesi]
2.  Site reddeder     →  access.log'a yazar
3.  Engine             →  Log'u izler (Layer 1)
4.  Regex eşleşir     →  "sqli" türünde olay üretilir
5.  Layer 2 puanlar   →  25 puan (sqli) + 20 puan (yabancı ülke) = 45
6.  Üçüncü denemede   →  25 × 3 + 20 = 95 puan → eşiği aşar
7.  Layer 3 engeller  →  nftables'a ekler, MySQL'e yazar
8.  Telegram bildirir →  "1.2.3.4 banlandı — sqli × 3 + yabancı"
9.  Dashboard         →  WebSocket ile anında günceller
```

---

## Akademik Bilgi

> Bu proje, **İstanbul Arel Üniversitesi Bilgisayar Mühendisliği Bölümü** bitirme tezi olarak hazırlanmıştır.

|  |  |
|---|---|
| Öğrenci | Mazlum Atila — 220309009 |
| Danışman | Dr. Tuğberk Kocatekin |
| Teslim | Haziran 2026 |

Tezin tamamına `docs/` klasörü altından erişilebilir.

---

## Gelecek Çalışmalar

- Makine öğrenmesi tabanlı anomali tespiti (autoencoder)
- Küresel tehdit istihbaratı entegrasyonu (AbuseIPDB)
- Docker konteyner desteği — tek komutla dağıtım
- Federe savunma ağı — birden fazla sunucu arası ban senkronizasyonu
- Büyük dil modeli tabanlı doğal dil özetleme

---

## Lisans

MIT License — detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

<div align="center">

*Bir IP'yi engellemek kolaydır. Saldırgan olduğunu kanıtlamak yetenek ister.*

İstanbul Arel Üniversitesi · 2026

</div>
