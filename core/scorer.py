"""
Adaptive Firewall — Katman 2: Risk Puanlama (Scorer)

Tespit edilen olayları çok sinyalli bir algoritmayla 0-100 arası puanlar.
Sinyaller:
  - Eşik aşımı       : Saldırı türünün eşiğini geçmesi
  - Yüksek hız       : Çok kısa sürede çok sayıda istek
  - Web saldırısı    : XSS/SQLi/path/command tek başına yüksek risk
  - Honeypot         : Tuzağa düşme = anında 100
  - Bot              : Kötü tarayıcı kullanımı
  - Gece çarpanı     : Gece saatlerinde gelen saldırılar daha riskli
  - Karma saldırı    : Birden fazla saldırı türü kullanma
  - Süreklilik       : Uzun süre devam eden saldırı
  - Yabancı ülke     : Güvenilir olmayan ülkeden geliş
"""

import time
from config import SCORE_WEIGHTS


# Web saldırıları — tek olay bile yüksek risk taşır
WEB_ATTACKS = {"xss", "sqli", "path_traversal", "command_injection"}


def calculate(profile: dict, settings: dict) -> dict:
    """
    Bir IP profilinin risk puanını hesapla.

    profile: {"ip": str, "events": [{time, type, detail}], "geo": {...}}
    settings: config.load_settings() çıktısı

    Döner: {"score": int, "reasons": [str], "attack_type": str}
    """
    now = time.time()
    events = profile["events"]
    geo = profile.get("geo", {})

    if not events:
        return {"score": 0, "reasons": [], "attack_type": None}

    total = 0
    reasons = []

    # Olayları türe göre say (zaman penceresi içinde)
    type_windows = {
        "brute_force": (settings["brute_force_count"], settings["brute_force_window"]),
        "port_scan": (settings["port_scan_count"], settings["port_scan_window"]),
        "ddos": (settings["ddos_count"], settings["ddos_window"]),
        "bot": (settings["bot_count"], settings["bot_window"]),
    }

    type_counts = {}
    dominant_type = None
    dominant_count = 0

    for atype, (threshold, window) in type_windows.items():
        recent = [e for e in events
                  if e["type"] == atype and now - e["time"] <= window]
        count = len(recent)
        type_counts[atype] = count
        if count >= threshold:
            ratio = count / threshold
            score = min(int(SCORE_WEIGHTS["threshold_hit"] * ratio), 50)
            total += score
            reasons.append(f"{atype}_esik_asildi ({count}/{threshold})")
            if count > dominant_count:
                dominant_count = count
                dominant_type = atype

    # Slow brute force — uzun pencerede yavaş ama ısrarlı denemeler
    slow_window = settings["slow_brute_window"]
    slow_threshold = settings["slow_brute_count"]
    slow_recent = [e for e in events
                   if e["type"] == "brute_force" and now - e["time"] <= slow_window]
    if len(slow_recent) >= slow_threshold and type_counts.get("brute_force", 0) < settings["brute_force_count"]:
        total += 45
        reasons.append(f"yavas_brute_force ({len(slow_recent)} deneme / {slow_window // 60}dk)")
        dominant_type = dominant_type or "brute_force"

    # Web saldırıları — tek olay bile ciddi
    web_events = [e for e in events if e["type"] in WEB_ATTACKS]
    if web_events:
        web_recent = [e for e in web_events
                      if now - e["time"] <= settings["web_attack_window"]]
        if web_recent:
            web_score = min(len(web_recent) * 20, SCORE_WEIGHTS["web_attack"])
            total += web_score
            wtypes = set(e["type"] for e in web_recent)
            reasons.append(f"web_saldirisi ({', '.join(wtypes)})")
            dominant_type = web_recent[-1]["type"]

    # Honeypot — anında maksimum
    honeypot_events = [e for e in events if e["type"] == "honeypot"]
    if honeypot_events:
        total = SCORE_WEIGHTS["honeypot"]
        reasons.append("honeypot_tuzagina_dustu")
        dominant_type = "honeypot"

    # Bot tespiti
    bot_events = [e for e in events if e["type"] == "bot"]
    if bot_events and type_counts.get("bot", 0) < settings["bot_count"]:
        total += SCORE_WEIGHTS["bot"]
        reasons.append("kotu_bot_tespit")
        dominant_type = dominant_type or "bot"

    # Yüksek hız cezası — son 10 saniyede 20+ olay
    very_recent = [e for e in events if now - e["time"] <= 10]
    if len(very_recent) >= 20:
        speed_score = min(len(very_recent) * 2, SCORE_WEIGHTS["high_speed"])
        total += speed_score
        reasons.append(f"yuksek_hiz ({len(very_recent)} olay/10sn)")

    # Karma saldırı bonusu — 2+ farklı tür
    active_types = set(e["type"] for e in events
                       if now - e["time"] <= 300)
    if len(active_types) >= 2:
        total += settings["mixed_attack_bonus"]
        reasons.append(f"karma_saldiri ({len(active_types)} tur)")
        dominant_type = "mixed"

    # Süreklilik cezası — 5+ dakika devam eden saldırı
    if len(events) >= 3:
        oldest = min(e["time"] for e in events)
        duration = now - oldest
        if duration >= 300:
            total += settings["persistent_penalty"]
            reasons.append(f"surekli_saldiri ({int(duration // 60)}dk)")

    # Gece saati çarpanı
    hour = time.localtime().tm_hour
    if settings["night_start"] <= hour <= settings["night_end"] and total > 0:
        bonus = int(total * settings["night_multiplier"] / 100)
        total += bonus
        reasons.append(f"gece_saati (+%{settings['night_multiplier']})")

    # Yabancı ülke cezası
    country = geo.get("country", "??")
    if country not in settings["trusted_countries"] and country not in ("LO", "??"):
        total += settings["foreign_penalty"]
        reasons.append(f"yabanci_ulke ({country})")

    total = min(total, 100)

    return {
        "score": total,
        "reasons": reasons,
        "attack_type": dominant_type or events[-1]["type"],
    }
