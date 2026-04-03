"""
GeoIP — IP adresinden ülke tespiti
Ücretsiz ip-api.com servisi kullanır, internet bağlantısı gerekir
"""

import urllib.request
import json
from functools import lru_cache

# Ülke bayrakları (emoji)
COUNTRY_FLAGS = {
    "TR": "🇹🇷", "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳",
    "DE": "🇩🇪", "FR": "🇫🇷", "GB": "🇬🇧", "NL": "🇳🇱",
    "BR": "🇧🇷", "IN": "🇮🇳", "KR": "🇰🇷", "JP": "🇯🇵",
    "UA": "🇺🇦", "IR": "🇮🇷", "PK": "🇵🇰", "NG": "🇳🇬",
    "VN": "🇻🇳", "ID": "🇮🇩", "TH": "🇹🇭", "MX": "🇲🇽",
}

@lru_cache(maxsize=1024)
def get_country(ip: str) -> dict:
    """
    IP adresinden ülke bilgisi al.
    Döner: {"country": "TR", "flag": "🇹🇷", "city": "Istanbul", "org": "ISP"}
    """
    # Lokal IP'ler için
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "::1", "local")):
        return {"country": "LO", "flag": "🏠", "city": "Localhost", "org": "Local"}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,org"
        req = urllib.request.Request(url, headers={"User-Agent": "3LayerFirewall/1.0"})
        with urllib.request.urlopen(req, timeout=3) as res:
            data = json.loads(res.read())
            code = data.get("countryCode", "??")
            return {
                "country": code,
                "flag": COUNTRY_FLAGS.get(code, "🌐"),
                "city": data.get("city", "?"),
                "org": data.get("org", "?"),
            }
    except Exception:
        return {"country": "??", "flag": "🌐", "city": "?", "org": "?"}


def format_geo(ip: str) -> str:
    """Terminal için kısa format: 🇷🇺 RU/Moskova"""
    geo = get_country(ip)
    return f"{geo['flag']} {geo['country']}/{geo['city']}"
