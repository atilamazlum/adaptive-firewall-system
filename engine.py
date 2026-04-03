"""
3LayerFirewall — Ana Motor
Layer 1 → 2 → 3 zinciri
"""

import time
import threading
from collections import defaultdict
import db
from config import THRESHOLDS, BAN_SCORE_THRESHOLD, WHITELIST
from log_parser import LogParser
from risk_scorer import calculate
from geoip import get_country
import nftables
import banner

class FirewallEngine:
    def __init__(self, log_path, dry_run=False):
        self.log_path = log_path
        self.dry_run = dry_run
        self.profiles = {}
        self.banned_ips = {}
        self.total_events = 0
        self.total_bans = 0
        self.parser = LogParser()
        self._lock = threading.Lock()

    def run(self):
        banner.banner()
        banner.info(f"Log izleniyor: {self.log_path}")
        banner.info(f"Mod: {'DRY RUN' if self.dry_run else 'CANLI'}")
        banner.info(f"Ban eşiği: {BAN_SCORE_THRESHOLD}\n")

        try:
            self._tail_log()
        except KeyboardInterrupt:
            banner.info("\nSistem durduruldu.")
            banner.summary(self.total_events, self.total_bans,
                          self.profiles, self.banned_ips)

    def _tail_log(self):
        with open(self.log_path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    self._process(line.strip())
                else:
                    time.sleep(0.1)

    def _process(self, line):
        event = self.parser.parse(line)
        if not event:
            return

        ip = event.get("ip")
        if not ip or ip in WHITELIST:
            return

        with self._lock:
            self.total_events += 1

            if ip not in self.profiles:
                self.profiles[ip] = {
                    "ip": ip,
                    "events": [],
                    "risk_score": 0,
                    "banned": False,
                    "geo": get_country(ip),
                }

            profile = self.profiles[ip]
            if profile["banned"]:
                return

            profile["events"].append({
                "time": time.time(),
                "type": event["type"],
                "detail": event.get("detail", ""),
            })

            # Eski olayları temizle
            max_window = max(t["window"] for t in THRESHOLDS.values())
            now = time.time()
            profile["events"] = [e for e in profile["events"]
                                  if now - e["time"] <= max_window]

            # Layer 2 — Risk skoru
            attack_type, score, reason, geo = calculate(profile)
            profile["risk_score"] = score
            profile["geo"] = geo

            banner.event(ip, event["type"], score, reason,
                        event.get("detail", ""), geo)

            # Layer 3 — Ban kararı
            if 40 <= score < BAN_SCORE_THRESHOLD:
                nftables.graylist(ip)
                banner.warn(f"GRAYLIST: {ip} izlemeye alındı (skor: {score})")
            if score >= BAN_SCORE_THRESHOLD:
                self._ban(ip, profile, attack_type, reason, geo)

    def _ban(self, ip, profile, attack_type, reason, geo):
        profile["banned"] = True
        self.banned_ips[ip] = {"time": time.time(), "geo": geo}
        db.ban(ip, reason=reason, score=profile["risk_score"], country=geo.get("country","??"), city=geo.get("city","?"))
        self.total_bans += 1

        banner.ban(ip, profile["risk_score"], attack_type, reason, geo)

        # Telegram bildirimi
        try:
            import urllib.request, json as _j
            _token = "YOUR_TELEGRAM_TOKEN"
            _chat = "6346333321"
            _msg = f"\U0001f6ab BAN: {ip}\n\U0001f30d {geo.get(chr(99)+chr(111)+chr(117)+chr(110)+chr(116)+chr(114)+chr(121),chr(63)+chr(63))}/{geo.get(chr(99)+chr(105)+chr(116)+chr(121),chr(63))}\n\u26a1 Skor: {profile[chr(114)+chr(105)+chr(115)+chr(107)+chr(95)+chr(115)+chr(99)+chr(111)+chr(114)+chr(101)]}/100"
            _data = _j.dumps({"chat_id": _chat, "text": _msg}).encode()
            _req = urllib.request.Request(f"https://api.telegram.org/bot{_token}/sendMessage", data=_data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(_req, timeout=3)
        except: pass

        if not self.dry_run:
            ok, msg = nftables.ban(ip)
            if ok:
                banner.info(f"nftables: {ip} engellendi")
            else:
                banner.warn(f"nftables hatası: {msg}")
        else:
            banner.warn(f"[DRY RUN] Ban atlandı: {ip}")

    def get_status(self):
        with self._lock:
            return {
                "total_events": self.total_events,
                "total_bans": self.total_bans,
                "banned_ips": list(self.banned_ips.keys()),
                "profiles": {
                    ip: {
                        "risk_score": p["risk_score"],
                        "banned": p["banned"],
                        "geo": p["geo"],
                        "event_count": len(p["events"]),
                    }
                    for ip, p in self.profiles.items()
                },
            }
