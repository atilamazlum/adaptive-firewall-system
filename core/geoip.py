"""
Adaptive Firewall — GeoIP Modülü
IP adreslerinin coğrafi konumunu (ülke, şehir) tespit eder.
ip-api.com ücretsiz servisini kullanır, sonuçlar cache'lenir.
"""

import urllib.request
import json
from functools import lru_cache


@lru_cache(maxsize=2048)
def lookup(ip: str) -> dict:
    """
    IP'nin coğrafi bilgisini döndür.
    Döner: {"country": "TR", "city": "Istanbul", "lat": .., "lon": ..}
    """
    # Yerel adresler
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "::1")) or ip == "localhost":
        return {"country": "LO", "city": "Local", "lat": 0.0, "lon": 0.0, "isp": "-"}

    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            f"?fields=status,countryCode,city,lat,lon,isp"
        )
        with urllib.request.urlopen(url, timeout=3) as res:
            data = json.loads(res.read())
            if data.get("status") == "success":
                return {
                    "country": data.get("countryCode", "??"),
                    "city": data.get("city", "?"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "isp": data.get("isp", "-"),
                }
    except Exception:
        pass

    return {"country": "??", "city": "?", "lat": 0.0, "lon": 0.0, "isp": "-"}
