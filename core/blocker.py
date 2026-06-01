"""
Adaptive Firewall — Katman 3: Engelleme (Blocker)

nftables araciligiyla IP adreslerini isletim sistemi seviyesinde engeller.
Hem IPv4 hem IPv6 destekler.

Kullanilan setler:
  fw_banned    -> engellenmis IPv4 adresleri
  fw_banned6   -> engellenmis IPv6 adresleri
  fw_graylist  -> izlenen supheli IPv4 adresleri
"""

import subprocess
from config import NFT_TABLE, NFT_FAMILY, NFT_BANNED_SET, NFT_GRAYLIST_SET

NFT_BANNED6_SET = "fw_banned6"


def _run(args: list) -> tuple:
    """nft komutu calistir. (basari, cikti) doner."""
    try:
        result = subprocess.run(
            ["nft"] + args,
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip()
    except FileNotFoundError:
        return False, "nft komutu bulunamadi (nftables kurulu mu?)"
    except Exception as e:
        return False, str(e)


def _is_ipv6(ip: str) -> bool:
    """IP adresi IPv6 mi?"""
    return ":" in ip


def setup() -> bool:
    """
    nftables tablo, set ve kurallarini olustur.
    Kurallar zaten varsa tekrar eklenmez (idempotent).
    """
    # Once mevcut input chain'i temizle — tekrar eden kural birikmesin
    _run(["flush", "chain", NFT_TABLE, NFT_FAMILY, "input"])

    commands = [
        ["add", "table", NFT_TABLE, NFT_FAMILY],
        # IPv4 banli seti
        ["add", "set", NFT_TABLE, NFT_FAMILY, NFT_BANNED_SET,
         "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
        # IPv6 banli seti
        ["add", "set", NFT_TABLE, NFT_FAMILY, NFT_BANNED6_SET,
         "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}"],
        # Graylist (IPv4)
        ["add", "set", NFT_TABLE, NFT_FAMILY, NFT_GRAYLIST_SET,
         "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
        # Input chain
        ["add", "chain", NFT_TABLE, NFT_FAMILY, "input",
         "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"],
        # IPv4 drop kurali
        ["add", "rule", NFT_TABLE, NFT_FAMILY, "input",
         "ip", "saddr", "@" + NFT_BANNED_SET, "drop"],
        # IPv6 drop kurali
        ["add", "rule", NFT_TABLE, NFT_FAMILY, "input",
         "ip6", "saddr", "@" + NFT_BANNED6_SET, "drop"],
    ]
    ok_all = True
    for cmd in commands:
        ok, msg = _run(cmd)
        if not ok and "exists" not in msg.lower():
            ok_all = False
    return ok_all


def ban(ip: str, duration: int = 0) -> tuple:
    """
    IP'yi banli setine ekle (IPv4 veya IPv6 otomatik secilir).
    duration saniye sonra otomatik duser (0 = kalici).
    """
    if duration > 0:
        element = f"{{ {ip} timeout {duration}s }}"
    else:
        element = f"{{ {ip} }}"

    target_set = NFT_BANNED6_SET if _is_ipv6(ip) else NFT_BANNED_SET
    return _run(["add", "element", NFT_TABLE, NFT_FAMILY, target_set, element])


def unban(ip: str) -> tuple:
    """IP'yi banli setinden cikar (IPv4 veya IPv6)."""
    target_set = NFT_BANNED6_SET if _is_ipv6(ip) else NFT_BANNED_SET
    return _run(["delete", "element", NFT_TABLE, NFT_FAMILY,
                 target_set, f"{{ {ip} }}"])


def graylist(ip: str, duration: int = 1800) -> tuple:
    """IP'yi izleme setine ekle (sadece IPv4)."""
    if _is_ipv6(ip):
        return True, "ipv6 graylist atlandi"
    element = f"{{ {ip} timeout {duration}s }}"
    return _run(["add", "element", NFT_TABLE, NFT_FAMILY,
                 NFT_GRAYLIST_SET, element])


def list_banned() -> list:
    """nftables'taki tum banli IP'leri dondur (IPv4 + IPv6)."""
    ips = []
    for set_name in (NFT_BANNED_SET, NFT_BANNED6_SET):
        ok, output = _run(["list", "set", NFT_TABLE, NFT_FAMILY, set_name])
        if not ok:
            continue
        for line in output.splitlines():
            line = line.strip()
            if "elements" in line or line.startswith("{") or line.startswith("}"):
                # elements = { ... } satirindaki IP'leri de al
                inner = line.split("{")[-1].split("}")[0]
                for token in inner.replace(",", " ").split():
                    if "." in token or ":" in token:
                        ips.append(token)
                continue
            for token in line.replace(",", " ").split():
                if token.count(".") == 3 or ":" in token:
                    ips.append(token)
    return ips


def flush() -> tuple:
    """Tum banlari temizle (IPv4 + IPv6)."""
    _run(["flush", "set", NFT_TABLE, NFT_FAMILY, NFT_BANNED_SET])
    return _run(["flush", "set", NFT_TABLE, NFT_FAMILY, NFT_BANNED6_SET])
