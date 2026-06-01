"""
Adaptive Firewall — Telegram Bot Komutlari

Telegram uzerinden uzaktan firewall yonetimi.
Long-polling ile getUpdates kullanir.

Komutlar:
  /stats     - Genel istatistikler
  /banlist   - Aktif banli IP'ler
  /ban IP    - Manuel ban
  /unban IP  - Bani kaldir
  /help      - Komut listesi
"""

import os
import time
import json
import threading
import urllib.request
import urllib.parse
import database as db
import blocker
from config import PROJECT_DIR


def _load_token():
    """token ve chat_id'yi .telegram dosyasindan oku."""
    path = os.path.join(PROJECT_DIR, ".telegram")
    if not os.path.exists(path):
        return None, None
    try:
        with open(path) as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        token = lines[0] if lines else None
        chat_id = lines[1] if len(lines) > 1 else None
        return token, chat_id
    except Exception:
        return None, None


def _send(token, chat_id, text):
    """Telegram'a mesaj gonder."""
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(url, data=data,
                                      headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print(f"[TELEGRAM] gonderme hatasi: {e}")
        return False


def _get_updates(token, offset):
    """Yeni mesajlari al."""
    try:
        params = urllib.parse.urlencode({
            "offset": offset, "timeout": 25,
        })
        url = f"https://api.telegram.org/bot{token}/getUpdates?{params}"
        with urllib.request.urlopen(url, timeout=30) as res:
            data = json.loads(res.read())
            if data.get("ok"):
                return data.get("result", [])
    except Exception:
        pass
    return []


# ─── KOMUT İSLEYİCİLERİ ──────────────────────────────────────────────────────

def cmd_help():
    return (
        "*Adaptive Firewall — Bot Komutlari*\n\n"
        "`/stats` — Genel istatistikler\n"
        "`/banlist` — Aktif banli IP'ler\n"
        "`/ban IP` — Manuel ban\n"
        "`/unban IP` — Bani kaldir\n"
        "`/help` — Bu mesaj"
    )


def cmd_stats():
    try:
        s = db.get_stats()
        msg = (
            "*ADAPTIVE FIREWALL — DURUM*\n\n"
            f"Toplam Olay : *{s['total_events']}*\n"
            f"Aktif Ban   : *{s['total_bans']}*\n"
            f"Izlenen IP  : *{s['unique_ips']}*\n"
            f"Son 24 saat : *{s['events_24h']}* olay\n"
        )
        if s.get("by_type"):
            msg += "\n*Saldiri Turleri:*\n"
            for t, c in list(s["by_type"].items())[:5]:
                msg += f"  • {t}: {c}\n"
        if s.get("by_country"):
            msg += "\n*En Cok Saldiri (Ulke):*\n"
            for ctry, c in list(s["by_country"].items())[:5]:
                msg += f"  • {ctry}: {c}\n"
        return msg
    except Exception as e:
        return f"Hata: {e}"


def cmd_banlist():
    try:
        bans = db.get_active_bans()
        if not bans:
            return "*Aktif banli IP yok.*"
        msg = f"*AKTIF BANLAR ({len(bans)})*\n\n"
        for b in bans[:15]:
            msg += (f"`{b['ip']}`\n"
                    f"  {b.get('attack_type','?')} | skor: {b.get('score',0)} "
                    f"| {b.get('country','??')}\n")
        if len(bans) > 15:
            msg += f"\n_...ve {len(bans)-15} ban daha_"
        return msg
    except Exception as e:
        return f"Hata: {e}"


def cmd_ban(ip):
    if not ip:
        return "Kullanim: `/ban 1.2.3.4`"
    try:
        db.ban(ip, reason="telegram_manual", score=100,
               attack_type="manual", country="??", city="?", duration=0)
        ok, _ = blocker.ban(ip, 0)
        nft_status = "nftables: OK" if ok else "nftables: hata"
        return f"*Banlandi:* `{ip}`\n_{nft_status}_"
    except Exception as e:
        return f"Hata: {e}"


def cmd_unban(ip):
    if not ip:
        return "Kullanim: `/unban 1.2.3.4`"
    try:
        db.unban(ip)
        blocker.unban(ip)
        return f"*Ban kaldirildi:* `{ip}`"
    except Exception as e:
        return f"Hata: {e}"


def _handle(text):
    """Gelen komutu isle, cevap doner."""
    text = text.strip()
    parts = text.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd in ("/start", "/help"):
        return cmd_help()
    if cmd == "/stats":
        return cmd_stats()
    if cmd == "/banlist":
        return cmd_banlist()
    if cmd == "/ban":
        return cmd_ban(arg)
    if cmd == "/unban":
        return cmd_unban(arg)
    return None  # tanimadigi mesaja cevap verme


# ─── BOT DONGUSU ─────────────────────────────────────────────────────────────

def _poll_loop():
    token, authorized_chat = _load_token()
    if not token:
        print("[TELEGRAM] .telegram dosyasi yok, bot pasif")
        return
    print(f"[TELEGRAM] Bot aktif, yetkili chat: {authorized_chat}")

    offset = 0
    while True:
        try:
            updates = _get_updates(token, offset)
            for u in updates:
                offset = u["update_id"] + 1
                msg = u.get("message")
                if not msg or "text" not in msg:
                    continue
                chat_id = str(msg["chat"]["id"])
                text = msg["text"]

                # Yetkilendirme — sadece tanimli chat
                if authorized_chat and chat_id != authorized_chat:
                    _send(token, chat_id, "Yetkisiz erisim.")
                    continue

                reply = _handle(text)
                if reply:
                    _send(token, chat_id, reply)
        except Exception as e:
            print(f"[TELEGRAM] poll hatasi: {e}")
            time.sleep(5)


def start():
    """Bot polling thread'ini baslat."""
    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    return t
