"""
Adaptive Firewall — Katman 1: Tespit (Detector)

Log satırlarını okur, regex tabanlı pattern eşleştirme ile saldırı tespiti yapar.
Desteklenen saldırı türleri:
  - brute_force      : SSH/HTTP şifre deneme
  - port_scan        : Çok sayıda porta bağlantı
  - ddos             : Flood / aşırı istek
  - xss              : Cross-site scripting denemesi
  - sqli             : SQL injection denemesi
  - path_traversal   : Dizin gezinme (../../etc/passwd)
  - command_injection: Komut enjeksiyonu
  - bot              : Kötü amaçlı bot/tarayıcı (sqlmap, nikto...)
  - honeypot         : Sahte tuzak endpoint'e erişim
"""

import re
from config import HONEYPOT_PATHS


class Detector:
    def __init__(self):
        self.patterns = self._build_patterns()

    def _build_patterns(self):
        return [
            # ── BRUTE FORCE ────────────────────────────────────────────────
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"Failed password for(?: invalid user)? (\S+) "
                    r"from ([\d.a-fA-F:]+) port (\d+)"
                ),
                "ip_group": 2,
                "detail": lambda m: f"user={m.group(1)} port={m.group(3)}",
            },
            {
                "type": "brute_force",
                "regex": re.compile(r"Invalid user (\S+) from ([\d.a-fA-F:]+)"),
                "ip_group": 2,
                "detail": lambda m: f"invalid_user={m.group(1)}",
            },
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"authentication failure.*rhost=([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: "pam_auth_failure",
            },
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"LOGIN_FAIL ip=([\d.a-fA-F:]+) user=(\S+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"web_login_fail user={m.group(2)}",
            },

            # ── PORT SCAN ──────────────────────────────────────────────────
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"Connection closed by ([\d.a-fA-F:]+) port (\d+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"port={m.group(2)}",
            },
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"Disconnected from ([\d.a-fA-F:]+) port (\d+) \[preauth\]"
                ),
                "ip_group": 1,
                "detail": lambda m: f"preauth port={m.group(2)}",
            },
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"PORT_SCAN ip=([\d.a-fA-F:]+) port=(\d+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"scan port={m.group(2)}",
            },

            # ── DDOS / FLOOD ───────────────────────────────────────────────
            {
                "type": "ddos",
                "regex": re.compile(
                    r"Did not receive identification string from ([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: "no_ident",
            },
            {
                "type": "ddos",
                "regex": re.compile(r"FLOOD ip=([\d.a-fA-F:]+) rate=(\d+)"),
                "ip_group": 1,
                "detail": lambda m: f"flood rate={m.group(2)}/s",
            },

            # ── XSS ────────────────────────────────────────────────────────
            {
                "type": "xss",
                "regex": re.compile(
                    r"([\d.a-fA-F:]+).*(?:<script|%3Cscript|javascript:|"
                    r"onerror=|onload=|<img[^>]+src)",
                    re.IGNORECASE
                ),
                "ip_group": 1,
                "detail": lambda m: "xss_payload",
            },
            {
                "type": "xss",
                "regex": re.compile(r"XSS_ATTEMPT ip=([\d.a-fA-F:]+) payload=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"xss={m.group(2)[:40]}",
            },

            # ── SQL INJECTION ──────────────────────────────────────────────
            {
                "type": "sqli",
                "regex": re.compile(
                    r"([\d.a-fA-F:]+).*(?:union\s+select|or\s+1=1|"
                    r"';\s*drop\s+table|--\s|/\*.*\*/|sleep\(\d+\))",
                    re.IGNORECASE
                ),
                "ip_group": 1,
                "detail": lambda m: "sqli_payload",
            },
            {
                "type": "sqli",
                "regex": re.compile(r"SQLI_ATTEMPT ip=([\d.a-fA-F:]+) payload=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"sqli={m.group(2)[:40]}",
            },

            # ── PATH TRAVERSAL ─────────────────────────────────────────────
            {
                "type": "path_traversal",
                "regex": re.compile(
                    r"([\d.a-fA-F:]+).*(?:\.\./\.\./|%2e%2e%2f|/etc/passwd|"
                    r"\.\.\\\.\.\\|c:\\windows)",
                    re.IGNORECASE
                ),
                "ip_group": 1,
                "detail": lambda m: "path_traversal",
            },
            {
                "type": "path_traversal",
                "regex": re.compile(r"PATH_TRAVERSAL ip=([\d.a-fA-F:]+) path=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"path={m.group(2)[:40]}",
            },

            # ── COMMAND INJECTION ──────────────────────────────────────────
            {
                "type": "command_injection",
                "regex": re.compile(
                    r"([\d.a-fA-F:]+).*(?:;\s*(?:cat|ls|wget|curl|rm|nc)\s|"
                    r"\|\s*(?:bash|sh)\s|`.*`|\$\(.*\))",
                    re.IGNORECASE
                ),
                "ip_group": 1,
                "detail": lambda m: "command_injection",
            },
            {
                "type": "command_injection",
                "regex": re.compile(r"CMD_INJECT ip=([\d.a-fA-F:]+) cmd=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"cmd={m.group(2)[:40]}",
            },

            # ── BOT / KÖTÜ TARAYICI ────────────────────────────────────────
            {
                "type": "bot",
                "regex": re.compile(
                    r"([\d.a-fA-F:]+).*\"(sqlmap|nikto|nmap|masscan|"
                    r"zgrab|dirbuster|gobuster|hydra|wpscan)",
                    re.IGNORECASE
                ),
                "ip_group": 1,
                "detail": lambda m: f"bot={m.group(2).lower()}",
            },
            {
                "type": "bot",
                "regex": re.compile(r"BAD_BOT ip=([\d.a-fA-F:]+) agent=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"agent={m.group(2)[:40]}",
            },

            # ── HONEYPOT ───────────────────────────────────────────────────
            {
                "type": "honeypot",
                "regex": re.compile(r"HONEYPOT ip=([\d.a-fA-F:]+) path=(.+)"),
                "ip_group": 1,
                "detail": lambda m: f"trap={m.group(2)}",
            },
        ]

    def _clean_ip(self, ip: str) -> str:
        """IPv6 önekini temizle (::ffff:1.2.3.4 → 1.2.3.4)."""
        return ip.replace("::ffff:", "").strip()

    # Site'in yazdigi ozel log formatlari (oncelikli — kesin eslesme)
    SITE_LOG_RE = re.compile(
        r"(LOGIN_FAIL|XSS_ATTEMPT|SQLI_ATTEMPT|PATH_TRAVERSAL|"
        r"CMD_INJECT|BAD_BOT|HONEYPOT|PORT_SCAN|FLOOD) "
        r"ip=([\d.a-fA-F:]+)(?: (?:user|payload|path|cmd|agent|port|rate)=(.+))?"
    )
    SITE_LOG_TYPE = {
        "LOGIN_FAIL": "brute_force",
        "XSS_ATTEMPT": "xss",
        "SQLI_ATTEMPT": "sqli",
        "PATH_TRAVERSAL": "path_traversal",
        "CMD_INJECT": "command_injection",
        "BAD_BOT": "bot",
        "HONEYPOT": "honeypot",
        "PORT_SCAN": "port_scan",
        "FLOOD": "ddos",
    }

    def parse(self, line: str):
        """
        Bir log satırını analiz et.
        Saldırı bulunursa dict döner, bulunmazsa None.

        Sıra önemli:
          1. Site'in özel log formatları (kesin eşleşme)
          2. Honeypot path kontrolü
          3. Genel regex pattern'leri (SSH, nginx vb.)
        """
        if not line:
            return None

        # 1. Site özel log formatı — en kesin, önce bunu dene
        sm = self.SITE_LOG_RE.search(line)
        if sm:
            tag = sm.group(1)
            ip = sm.group(2)
            extra = sm.group(3) or ""
            return {
                "type": self.SITE_LOG_TYPE[tag],
                "ip": self._clean_ip(ip),
                "detail": (tag.lower() + (" " + extra[:40] if extra else "")),
                "raw": line,
            }

        # 2. Honeypot path kontrolü
        for hp in HONEYPOT_PATHS:
            if hp in line:
                ip_match = re.search(r"([\d]{1,3}(?:\.[\d]{1,3}){3})", line)
                if ip_match:
                    return {
                        "type": "honeypot",
                        "ip": self._clean_ip(ip_match.group(1)),
                        "detail": f"trap={hp}",
                        "raw": line,
                    }

        # 3. Genel regex pattern'leri
        for pattern in self.patterns:
            m = pattern["regex"].search(line)
            if not m:
                continue
            ip = m.group(pattern["ip_group"])
            if not ip:
                continue
            return {
                "type": pattern["type"],
                "ip": self._clean_ip(ip),
                "detail": pattern["detail"](m),
                "raw": line,
            }

        return None
