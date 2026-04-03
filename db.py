import sqlite3
import time
import os

DB_PATH = os.path.expanduser("~/firewall-v2/bans.db")

def init():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            score INTEGER,
            country TEXT,
            city TEXT,
            banned_at REAL,
            expires_at REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            type TEXT,
            detail TEXT,
            ts REAL
        )
    """)
    conn.commit()
    conn.close()

def ban(ip, reason="", score=0, country="??", city="?", duration=3600):
    conn = sqlite3.connect(DB_PATH)
    now = time.time()
    conn.execute("""
        INSERT OR REPLACE INTO banned_ips
        (ip, reason, score, country, city, banned_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip, reason, score, country, city, now, now + duration if duration else None))
    conn.commit()
    conn.close()

def unban(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

def is_banned(ip):
    conn = sqlite3.connect(DB_PATH)
    now = time.time()
    row = conn.execute("""
        SELECT ip FROM banned_ips
        WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)
    """, (ip, now)).fetchone()
    conn.close()
    return row is not None

def get_all_banned():
    conn = sqlite3.connect(DB_PATH)
    now = time.time()
    rows = conn.execute("""
        SELECT ip, reason, score, country, city, banned_at, expires_at
        FROM banned_ips WHERE expires_at IS NULL OR expires_at > ?
        ORDER BY banned_at DESC
    """, (now,)).fetchall()
    conn.close()
    return [{"ip": r[0], "reason": r[1], "score": r[2], "country": r[3],
             "city": r[4], "banned_at": r[5], "expires_at": r[6]} for r in rows]

def log_event(ip, etype, detail=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO events (ip, type, detail, ts) VALUES (?, ?, ?, ?)",
                 (ip, etype, detail, time.time()))
    conn.commit()
    conn.close()

def cleanup_expired():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM banned_ips WHERE expires_at IS NOT NULL AND expires_at < ?", (time.time(),))
    conn.commit()
    conn.close()

init()
