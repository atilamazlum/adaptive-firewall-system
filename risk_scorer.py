"""
Layer 2 — Risk Scorer
Çok sinyalli IP puanlama sistemi
GeoIP, hız, saat, süreklilik, karma saldırı
"""

import time
from config import THRESHOLDS, SCORE_WEIGHTS, TRUSTED_COUNTRIES
from geoip import get_country


def calculate(profile: dict) -> tuple:
    """
    IP profilini analiz eder.
    Döner: (dominant_type, score, reason)
    """
    now = time.time()
    events = profile["events"]
    total_score = 0
    reasons = []
    dominant_type = None
    dominant_count = 0

    # ── Layer 2A: Eşik kontrolü ───────────────────────────────────────────────
    type_counts = {}
    for event_type, cfg in THRESHOLDS.items():
        window = cfg["window"]
        threshold = cfg["count"]

        recent = [e for e in events
                  if e["type"] == event_type
                  and now - e["time"] <= window]
        count = len(recent)
        type_counts[event_type] = count

        if count >= threshold:
            ratio = count / threshold
            score = min(int(SCORE_WEIGHTS["threshold_hit"] * ratio), 50)
            total_score += score
            reasons.append(f"{event_type}={count}")

            if count > dominant_count:
                dominant_count = count
                dominant_type = event_type

    # ── Layer 2B: Hız cezası ─────────────────────────────────────────────────
    very_recent = [e for e in events if now - e["time"] <= 10]
    if len(very_recent) >= 20:
        speed_score = min(len(very_recent) * 2, SCORE_WEIGHTS["high_speed"])
        total_score += speed_score
        reasons.append(f"high_speed={len(very_recent)}/10s")

    # ── Layer 2C: Gece saati cezası (00:00-05:00) ────────────────────────────
    hour = time.localtime().tm_hour
    if 0 <= hour <= 5 and total_score > 0:
        bonus = int(total_score * (SCORE_WEIGHTS["night_penalty"] / 100))
        total_score += bonus
        reasons.append("night_penalty")

    # ── Layer 2D: Karma saldırı bonusu ───────────────────────────────────────
    active_types = [t for t, c in type_counts.items() if c > 0]
    if len(active_types) >= 2:
        total_score += SCORE_WEIGHTS["mixed_attack"]
        reasons.append(f"mixed({len(active_types)}_types)")
        dominant_type = "mixed"

    # ── Layer 2E: Süreklilik cezası ──────────────────────────────────────────
    if len(events) >= 3:
        oldest = min(e["time"] for e in events)
        duration = now - oldest
        if duration >= 300:
            total_score += SCORE_WEIGHTS["persistent"]
            reasons.append(f"persistent={int(duration)}s")

    # ── Layer 2F: GeoIP cezası ───────────────────────────────────────────────
    ip = profile["ip"]
    geo = get_country(ip)
    if geo["country"] not in TRUSTED_COUNTRIES and geo["country"] not in ("LO", "??"):
        total_score += SCORE_WEIGHTS["foreign_ip"]
        reasons.append(f"foreign={geo['flag']}{geo['country']}")

    total_score = min(total_score, 100)
    reason_str = " | ".join(reasons) if reasons else "normal"

    return dominant_type, total_score, reason_str, geo
