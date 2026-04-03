# ─── 3LayerFirewall — Merkezi Konfigürasyon ───────────────────────────────────

# Log dosyası
LOG_PATH = "/var/log/auth.log"

# Ban eşiği (0-100)
BAN_SCORE_THRESHOLD = 70

# Whitelist — asla banlanmaz
WHITELIST = {}

# Ban süresi (saniye) — None = kalıcı
BAN_DURATION = 3600  # 1 saat

# ─── Katman 1 — Tespit Eşikleri ──────────────────────────────────────────────
THRESHOLDS = {
    "brute_force":  {"count": 5,   "window": 60},
    "port_scan":    {"count": 10,  "window": 30},
    "ddos":         {"count": 100, "window": 10},
    "http_anomaly": {"count": 20,  "window": 60},
}

# ─── Katman 2 — Risk Skoru Ağırlıkları ───────────────────────────────────────
SCORE_WEIGHTS = {
    "threshold_hit":  50,   # Eşik aşıldı
    "high_speed":     30,   # Yüksek hız
    "night_penalty":  25,   # Gece saati
    "mixed_attack":   15,   # Karma saldırı
    "persistent":     10,   # Süreklilik
    "foreign_ip":     20,   # Yabancı ülke (GeoIP)
}

# ─── Katman 3 — Aksiyon ──────────────────────────────────────────────────────
NFTABLES_TABLE = "inet"
NFTABLES_SET   = "banned_ips"
DRY_RUN        = False   # True → ban yok, sadece göster

# ─── GeoIP ───────────────────────────────────────────────────────────────────
TRUSTED_COUNTRIES = {"TR"}   # Bu ülkelerden gelen IP'lere bonus
