"""
Adaptive Firewall — Ana Motor (Engine)

Üç katmanı koordine eder:
  Layer 1 (detector) → Layer 2 (scorer) → Layer 3 (blocker)

Log dosyasını gerçek zamanlı izler, saldırı tespit eder,
risk puanı hesaplar ve eşik aşılırsa IP'yi engeller.
"""

import time
import threading
import os

import config
import database as db
from detector import Detector
from scorer import calculate
from geoip import lookup
import blocker
import telegram_bot

# ANSI renkler — terminal çıktısı için
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


# Saldırı türü → görünen isim
TYPE_NAMES = {
    "brute_force": "Brute Force",
    "port_scan": "Port Tarama",
    "ddos": "DDoS / Flood",
    "xss": "XSS",
    "sqli": "SQL Injection",
    "path_traversal": "Path Traversal",
    "command_injection": "Komut Enjeksiyonu",
    "bot": "Kotu Bot",
    "honeypot": "Honeypot",
    "mixed": "Karma Saldiri",
}


class FirewallEngine:
    def __init__(self, log_path=None, dry_run=False):
        self.log_path = log_path or config.LOG_PATH
        self.dry_run = dry_run
        self.detector = Detector()
        self.profiles = {}          # ip -> {events, score, banned, geo}
        self.settings = config.load_settings()
        self.total_events = 0
        self.total_bans = 0
        self._lock = threading.Lock()
        self._running = False
        self._settings_mtime = 0

    # ── AYAR YENİDEN YÜKLEME ──────────────────────────────────────────────────
    def _reload_settings_if_changed(self):
        """settings.json değiştiyse ayarları yeniden yükle (dashboard değişikliği)."""
        try:
            mtime = os.path.getmtime(config.SETTINGS_PATH)
            if mtime != self._settings_mtime:
                self._settings_mtime = mtime
                self.settings = config.load_settings()
                self._log(C.CYAN, "AYAR", "Ayarlar yeniden yuklendi")
        except OSError:
            pass

    # ── TERMINAL ÇIKTISI ──────────────────────────────────────────────────────
    def _log(self, color, tag, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"{C.GRAY}{ts}{C.RESET} {color}[{tag}]{C.RESET} {msg}")

    def _banner(self):
        print(f"\n{C.BOLD}{C.CYAN}{'=' * 56}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}   ADAPTIVE FIREWALL SYSTEM{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}   3 Katmanli Adaptif Guvenlik Duvari{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'=' * 56}{C.RESET}")
        mode = "DRY-RUN (engelleme yok)" if self.dry_run else "CANLI"
        print(f"  Mod        : {mode}")
        print(f"  Log        : {self.log_path}")
        print(f"  Ban esigi  : {self.settings['ban_score']} puan")
        print(f"{C.CYAN}{'=' * 56}{C.RESET}\n")

    def _score_bar(self, score):
        """Puanı görsel bar olarak göster."""
        filled = int(score / 10)
        bar = "#" * filled + "." * (10 - filled)
        if score >= self.settings["ban_score"]:
            color = C.RED
        elif score >= self.settings["graylist_score"]:
            color = C.YELLOW
        else:
            color = C.GREEN
        return f"{color}[{bar}] {score:3d}{C.RESET}"

    # ── ANA İŞLEME ────────────────────────────────────────────────────────────
    def _process_line(self, line):
        event = self.detector.parse(line)
        if not event:
            return

        ip = event["ip"]
        if ip in config.WHITELIST:
            return

        with self._lock:
            self.total_events += 1

            if ip not in self.profiles:
                geo = lookup(ip)
                self.profiles[ip] = {
                    "ip": ip,
                    "events": [],
                    "score": 0,
                    "banned": False,
                    "geo": geo,
                }

            profile = self.profiles[ip]

            # Banlıysa ama DB'de değilse (unban yapılmış) — profili sıfırla
            if profile["banned"]:
                if not db.is_banned(ip):
                    profile["banned"] = False
                    profile["events"] = []
                    profile["score"] = 0
                else:
                    return

            # Olayı ekle
            profile["events"].append({
                "time": time.time(),
                "type": event["type"],
                "detail": event["detail"],
            })

            # Eski olayları temizle (30 dakikadan eski)
            now = time.time()
            profile["events"] = [
                e for e in profile["events"] if now - e["time"] <= 1800
            ]

            # Layer 2 — Risk puanı
            result = calculate(profile, self.settings)
            score = result["score"]
            profile["score"] = score
            attack_type = result["attack_type"]

            geo = profile["geo"]
            country = geo.get("country", "??")

            # Olayı veritabanına kaydet
            db.log_event(ip, event["type"], event["detail"], score, country)

            # Terminal çıktısı
            type_name = TYPE_NAMES.get(event["type"], event["type"])
            self._log(
                C.BLUE, "TESPIT",
                f"{ip:15s} {type_name:18s} {self._score_bar(score)} "
                f"{C.GRAY}{country}{C.RESET}"
            )

            # Layer 3 — Karar
            if score >= self.settings["ban_score"]:
                self._ban(ip, profile, attack_type, result["reasons"])
            elif score >= self.settings["graylist_score"]:
                if not self.dry_run:
                    blocker.graylist(ip)
                self._log(C.YELLOW, "IZLEME",
                          f"{ip} graylist'e alindi (skor: {score})")

    def _ban(self, ip, profile, attack_type, reasons):
        profile["banned"] = True
        self.total_bans += 1
        geo = profile["geo"]
        score = profile["score"]
        reason_str = " | ".join(reasons)

        # Veritabanı
        db.ban(ip, reason=reason_str, score=score, attack_type=attack_type,
               country=geo.get("country", "??"), city=geo.get("city", "?"),
               duration=self.settings["ban_duration"])

        # nftables
        if not self.dry_run:
            ok, msg = blocker.ban(ip, self.settings["ban_duration"])
            nft_status = "engellendi" if ok else f"HATA: {msg}"
        else:
            nft_status = "[dry-run]"

        # Terminal — ban kutusu
        type_name = TYPE_NAMES.get(attack_type, attack_type)
        print(f"\n{C.RED}{C.BOLD}  +{'-' * 48}+{C.RESET}")
        print(f"{C.RED}{C.BOLD}  |  BAN KARARI VERILDI{' ' * 28}|{C.RESET}")
        print(f"{C.RED}  |  IP        : {ip:<33s}|{C.RESET}")
        print(f"{C.RED}  |  Konum     : {geo.get('country','??')}/{geo.get('city','?'):<28s}|{C.RESET}")
        print(f"{C.RED}  |  Saldiri   : {type_name:<33s}|{C.RESET}")
        print(f"{C.RED}  |  Risk Skor : {str(score) + '/100':<33s}|{C.RESET}")
        print(f"{C.RED}  |  nftables  : {nft_status:<33s}|{C.RESET}")
        print(f"{C.RED}{C.BOLD}  +{'-' * 48}+{C.RESET}\n")

        # Telegram bildirimi
        self._notify_telegram(ip, geo, score, type_name, reason_str)

    def _notify_telegram(self, ip, geo, score, type_name, reason):
        """Telegram'a ban bildirimi gönder (token varsa)."""
        token_path = os.path.join(config.PROJECT_DIR, ".telegram")
        if not os.path.exists(token_path):
            return
        try:
            import urllib.request
            import json
            with open(token_path) as f:
                lines = f.read().strip().split("\n")
            token = lines[0].strip()
            chat_id = lines[1].strip() if len(lines) > 1 else ""
            if not token or not chat_id:
                return
            msg = (
                f"ADAPTIVE FIREWALL - BAN\n\n"
                f"IP: {ip}\n"
                f"Konum: {geo.get('country','??')}/{geo.get('city','?')}\n"
                f"Saldiri: {type_name}\n"
                f"Risk Skoru: {score}/100\n"
                f"Neden: {reason}"
            )
            data = json.dumps({"chat_id": chat_id, "text": msg}).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data=data, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass

    # ── LOG İZLEME ────────────────────────────────────────────────────────────
    def _tail_log(self):
        """Log dosyasını tail -f gibi sürekli izle."""
        # Dosya yoksa oluştur
        if not os.path.exists(self.log_path):
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            open(self.log_path, "a").close()

        with open(self.log_path, "r") as f:
            f.seek(0, 2)  # Dosya sonuna git
            while self._running:
                line = f.readline()
                if line:
                    self._process_line(line.strip())
                else:
                    time.sleep(0.2)
                    self._reload_settings_if_changed()

    def _cleanup_loop(self):
        """Periyodik olarak süresi dolmuş banları temizle."""
        while self._running:
            time.sleep(60)
            db.cleanup_expired()

    # ── BAŞLATMA ──────────────────────────────────────────────────────────────
    def run(self):
        db.init()
        self._banner()
        telegram_bot.start()
        self._log(C.GREEN, "TELEGRAM", "Bot komut dinleyicisi aktif")

        if not self.dry_run:
            ok = blocker.setup()
            if ok:
                self._log(C.GREEN, "NFT", "nftables tablo ve setleri hazir")
            else:
                self._log(C.YELLOW, "NFT",
                          "nftables kurulamadi (root gerekebilir)")

            # Kalici ban geri yukleme — program kapanip acilinca
            # nftables sifirlanir, MySQL'deki aktif banlari geri yukle
            self._restore_bans()

        # Restart sonrasi — MySQL'deki aktif banlari nftables'a geri yukle
        self._restore_bans()

        self._log(C.GREEN, "BASLADI", f"Log izleniyor: {self.log_path}")
        print()

        self._running = True

        # Temizlik thread'i
        cleanup = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup.start()

        try:
            self._tail_log()
        except KeyboardInterrupt:
            self._running = False
            print(f"\n{C.YELLOW}Sistem durduruluyor...{C.RESET}")
            self._summary()

    def _restore_bans(self):
        """
        Program yeniden baslatildiginda MySQL'deki aktif banlari
        nftables'a geri yukler. nftables restart'ta sifirlandigi icin
        bu adim kalici banlarin korunmasini saglar.
        """
        try:
            active = db.get_active_bans()
        except Exception as e:
            self._log(C.YELLOW, "GERI-YUKLE", f"Ban listesi okunamadi: {e}")
            return

        if not active:
            return

        restored = 0
        for ban in active:
            ip = ban["ip"]
            # Profili banli olarak isaretle
            self.profiles[ip] = {
                "ip": ip, "events": [], "score": ban.get("score", 100),
                "banned": True,
                "geo": {"country": ban.get("country", "??"),
                        "city": ban.get("city", "?")},
            }
            # nftables'a geri ekle (kalici — duration 0)
            if not self.dry_run:
                blocker.ban(ip, 0)
            restored += 1

        self._log(C.GREEN, "GERI-YUKLE",
                  f"{restored} kalici ban nftables'a geri yuklendi")

    def _restore_bans(self):
        """
        Program baslangicinda MySQL'deki aktif banlari nftables'a geri yukler.
        nftables restart'ta sifirlandigi icin kalici banlar bu sayede korunur.
        """
        try:
            active = db.get_active_bans()
        except Exception as e:
            self._log(C.YELLOW, "GERI-YUKLEME", f"Banlar okunamadi: {e}")
            return

        if not active:
            self._log(C.GRAY, "GERI-YUKLEME", "Geri yuklenecek aktif ban yok")
            return

        restored = 0
        for ban in active:
            ip = ban["ip"]
            ok, _ = blocker.ban(ip, 0)  # 0 = kalici
            if ok:
                restored += 1
            # Profili de banli olarak isaretle
            self.profiles[ip] = {
                "ip": ip, "events": [], "score": ban.get("score", 100),
                "banned": True,
                "geo": {"country": ban.get("country", "??"),
                        "city": ban.get("city", "?")},
            }
        self._log(C.GREEN, "GERI-YUKLEME",
                  f"{restored} kalici ban nftables'a geri yuklendi")

    def _summary(self):
        print(f"\n{C.CYAN}{'=' * 40}{C.RESET}")
        print(f"  Toplam olay  : {self.total_events}")
        print(f"  Toplam ban   : {self.total_bans}")
        print(f"  Izlenen IP   : {len(self.profiles)}")
        print(f"{C.CYAN}{'=' * 40}{C.RESET}\n")
