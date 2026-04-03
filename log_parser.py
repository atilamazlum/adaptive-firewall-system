"""
Layer 1 — Log Parser
auth.log, syslog, nginx/apache loglarını okur
Brute force, port scan, DDoS, HTTP anomali tespiti
"""

import re
from typing import Optional


class LogParser:
    def __init__(self):
        self.patterns = [

            # SSH brute force
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"Failed password for(?: invalid user)? (\S+) from ([\d.a-fA-F:]+) port (\d+)"
                ),
                "ip_group": 2,
                "detail": lambda m: f"user={m.group(1)} port={m.group(3)}",
            },

            # Geçersiz kullanıcı
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"Invalid user (\S+) from ([\d.a-fA-F:]+)"
                ),
                "ip_group": 2,
                "detail": lambda m: f"invalid_user={m.group(1)}",
            },

            # Max auth exceeded
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"error: maximum authentication attempts exceeded.*from ([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: "max_auth_exceeded",
            },

            # PAM auth failure
            {
                "type": "brute_force",
                "regex": re.compile(
                    r"pam_unix\(sshd:auth\): authentication failure.*rhost=([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"pam_fail rhost={m.group(1)}",
            },

            # Port tarama — bağlantı kesilmesi
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"Connection closed by ([\d.a-fA-F:]+) port (\d+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"port={m.group(2)}",
            },

            # Port tarama — preauth
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"Disconnected from ([\d.a-fA-F:]+) port (\d+) \[preauth\]"
                ),
                "ip_group": 1,
                "detail": lambda m: f"preauth port={m.group(2)}",
            },

            # Port tarama — negotiate fail
            {
                "type": "port_scan",
                "regex": re.compile(
                    r"Unable to negotiate with ([\d.a-fA-F:]+) port (\d+)"
                ),
                "ip_group": 1,
                "detail": lambda m: f"negotiate_fail port={m.group(2)}",
            },

            # DDoS — no ident
            {
                "type": "ddos",
                "regex": re.compile(
                    r"Did not receive identification string from ([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: "no_ident",
            },

            # DDoS — timeout
            {
                "type": "ddos",
                "regex": re.compile(
                    r"Connection timed out.*from ([\d.a-fA-F:]+)"
                ),
                "ip_group": 1,
                "detail": lambda m: "timeout",
            },

            # HTTP anomali — nginx 4xx
            {
                "type": "http_anomaly",
                "regex": re.compile(
                    r'"(?:GET|POST|PUT|DELETE|HEAD) .+ HTTP/[\d.]+" (4\d{2}) .+ "([\d.]+)"'
                ),
                "ip_group": 2,
                "detail": lambda m: f"http_{m.group(1)}",
            },

            # Suspicious agent — sqlmap, nikto, nmap
            {
                "type": "http_anomaly",
                "regex": re.compile(
                    r'([\d.]+).*"[^"]*" \d+ \d+ "[^"]*" "(sqlmap|nikto|nmap|masscan|zgrab|curl/7\.[0-4])'
                ),
                "ip_group": 1,
                "detail": lambda m: f"suspicious_agent={m.group(2)}",
            },
        ]

    def parse(self, line: str) -> Optional[dict]:
        for pattern in self.patterns:
            m = pattern["regex"].search(line)
            if not m:
                continue

            ip = m.group(pattern["ip_group"])
            if not ip:
                continue

            return {
                "type": pattern["type"],
                "ip": ip,
                "detail": pattern["detail"](m),
                "raw": line,
            }

        return None
