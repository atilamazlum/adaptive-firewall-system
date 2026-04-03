"""
Terminal Display — Renkli ve okunaklı terminal çıktısı
"""

import time
from datetime import datetime

# ─── ANSI Renk kodları ────────────────────────────────────────────────────────
R    = "\033[91m"
Y    = "\033[93m"
G    = "\033[92m"
B    = "\033[94m"
C    = "\033[96m"
M    = "\033[95m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def _score_color(score):
    if score >= 70: return R
    if score >= 40: return Y
    return G

def _bar(score, width=20):
    filled = int(score / 100 * width)
    color = _score_color(score)
    return f"{color}{'█' * filled}{'░' * (width - filled)}{RST}"


def banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════════╗
║         3LayerFirewall — IDS/IPS Güvenlik Sistemi        ║
║   Layer1: Tespit | Layer2: Puanlama | Layer3: Engelleme  ║
╚══════════════════════════════════════════════════════════╝{RST}
""")

def info(msg):
    print(f"{DIM}[{_ts()}]{RST} {G}[INFO]{RST}  {msg}")

def warn(msg):
    print(f"{DIM}[{_ts()}]{RST} {Y}[WARN]{RST}  {msg}")

def event(ip, event_type, score, reason, detail, geo):
    color = _score_color(score)
    bar = _bar(score, width=15)

    type_label = {
        "brute_force":  f"{R}[BRUTE]{RST}",
        "port_scan":    f"{Y}[SCAN ]{RST}",
        "ddos":         f"{M}[DDOS ]{RST}",
        "http_anomaly": f"{B}[HTTP ]{RST}",
        "mixed":        f"{C}[MIXED]{RST}",
    }.get(event_type, f"{DIM}[?????]{RST}")

    geo_str = f"{geo['flag']} {geo['country']}/{geo['city']}"
    score_str = f"{color}{score:3d}{RST}"
    detail_str = f" {DIM}({detail}){RST}" if detail else ""

    print(
        f"{DIM}[{_ts()}]{RST} {type_label} "
        f"{BOLD}{ip:<16}{RST} "
        f"{DIM}{geo_str:<20}{RST} "
        f"skor={score_str} {bar} "
        f"{DIM}{reason}{RST}"
        f"{detail_str}"
    )

def ban(ip, score, attack_type, reason, geo):
    print(f"""
{R}{BOLD}╔══════════════════════════════════════════════════════════╗
║  🚫  BAN KARARI VERİLDİ — LAYER 3 AKTİF                 ║
╠══════════════════════════════════════════════════════════╣{RST}
{R}║{RST}  IP      : {BOLD}{ip}{RST}
{R}║{RST}  Konum   : {geo['flag']} {geo['country']} / {geo['city']}
{R}║{RST}  ISP     : {DIM}{geo['org']}{RST}
{R}║{RST}  Skor    : {BOLD}{score}/100{RST}
{R}║{RST}  Tür     : {BOLD}{attack_type}{RST}
{R}║{RST}  Neden   : {DIM}{reason}{RST}
{R}║{RST}  Zaman   : {_ts()}
{R}{BOLD}╚══════════════════════════════════════════════════════════╝{RST}
""")

def summary(total_events, total_bans, profiles, banned_ips):
    print(f"""
{C}{BOLD}═══════════════ OTURUM ÖZETİ ═══════════════{RST}
  Toplam olay  : {BOLD}{total_events}{RST}
  Banlanan IP  : {BOLD}{R}{total_bans}{RST}
  İzlenen IP   : {BOLD}{len(profiles)}{RST}
""")
    if banned_ips:
        print(f"{Y}Banlanan IPler:{RST}")
        for ip, data in banned_ips.items():
            elapsed = int(time.time() - data["time"])
            geo = data.get("geo", {})
            flag = geo.get("flag", "🌐")
            country = geo.get("country", "??")
            print(f"  {R}•{RST} {ip:<20} {flag} {country:<5} {DIM}(+{elapsed}s önce){RST}")

    print(f"\n{Y}Risk skorları:{RST}")
    sorted_p = sorted(profiles.items(), key=lambda x: x[1]["risk_score"], reverse=True)
    for ip, p in sorted_p[:10]:
        bar = _bar(p["risk_score"], width=12)
        banned_tag = f" {R}[BANLANDI]{RST}" if p["banned"] else ""
        geo = p.get("geo", {})
        flag = geo.get("flag", "🌐")
        print(f"  {ip:<20} {flag} {bar} {p['risk_score']:3d}{banned_tag}")
    print()
