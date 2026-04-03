"""
Layer 3 — nftables Yönetimi
"""

import subprocess
from config import NFTABLES_TABLE, NFTABLES_SET, DRY_RUN, WHITELIST

RULES = """table inet filter {
    set banned_ips {
        type ipv4_addr
        flags dynamic, timeout
        timeout 1h
    }
    set graylisted_ips {
        type ipv4_addr
        flags dynamic, timeout
        timeout 30m
    }
    set whitelisted_ips {
        type ipv4_addr
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @whitelisted_ips accept
        ip saddr @banned_ips drop
        iif lo accept
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport 443 accept
        ip protocol icmp accept
        ip saddr @graylisted_ips accept
        log prefix "3lf-drop: " level warn
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}"""

def setup():
    try:
        proc = subprocess.run(["nft", "-f", "-"], input=RULES, text=True, capture_output=True)
        if proc.returncode == 0:
            return True, "nftables kuruldu"
        return False, proc.stderr.strip()
    except FileNotFoundError:
        return False, "nft bulunamadı"

def ban(ip):
    if ip in WHITELIST:
        return False, "whitelist'te"
    if DRY_RUN:
        return True, "dry-run"
    import re
    is_ipv6 = ":" in ip
    set_name = "banned_ips6" if is_ipv6 else "banned_ips"
    cmd = ["nft", "add", "element", "inet", "filter", set_name, f"{{{ip}}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode == 0, proc.stderr.strip()
    except FileNotFoundError:
        return False, "nft bulunamadı"

def graylist(ip):
    if DRY_RUN:
        return True, "dry-run"
    cmd = ["nft", "add", "element", "inet", "filter", "graylisted_ips", f"{{{ip}}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode == 0, proc.stderr.strip()
    except FileNotFoundError:
        return False, "nft bulunamadı"

def whitelist_add(ip):
    cmd = ["nft", "add", "element", "inet", "filter", "whitelisted_ips", f"{{{ip}}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode == 0, proc.stderr.strip()
    except FileNotFoundError:
        return False, "nft bulunamadı"

def unban(ip):
    cmd = ["nft", "delete", "element", "inet", "filter", "banned_ips", f"{{{ip}}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return proc.returncode == 0, proc.stderr.strip()
    except FileNotFoundError:
        return False, "nft bulunamadı"

def list_banned():
    try:
        proc = subprocess.run(["nft", "list", "set", "inet", "filter", "banned_ips"], capture_output=True, text=True)
        return proc.stdout if proc.returncode == 0 else ""
    except FileNotFoundError:
        return ""
