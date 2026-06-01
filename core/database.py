"""
Adaptive Firewall — Veritabani Katmani (MySQL)
SQLite yerine MySQL kullanir. Kalici ban yonetimi ve olay kaydi.

Tablolar:
  banned_ips  -> aktif ve gecmis banlar
  events      -> tespit edilen tum saldiri olaylari
  ip_profiles -> IP bazli ozet istatistik
"""

import time
import threading
import mysql.connector
from mysql.connector import pooling
from config import DB_CONFIG

_lock = threading.Lock()
_pool = None


def _get_pool():
    """MySQL baglanti havuzu (lazy init)."""
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="fw_pool",
            pool_size=5,
            **DB_CONFIG
        )
    return _pool


def _conn():
    return _get_pool().get_connection()


def init():
    """Tablolari olustur (yoksa)."""
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip          VARCHAR(45) PRIMARY KEY,
                reason      TEXT NOT NULL,
                score       INT NOT NULL DEFAULT 0,
                attack_type VARCHAR(40),
                country     VARCHAR(8) DEFAULT '??',
                city        VARCHAR(80) DEFAULT '?',
                banned_at   DOUBLE NOT NULL,
                expires_at  DOUBLE,
                active      TINYINT NOT NULL DEFAULT 1
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          BIGINT PRIMARY KEY AUTO_INCREMENT,
                ip          VARCHAR(45) NOT NULL,
                attack_type VARCHAR(40) NOT NULL,
                detail      TEXT,
                score       INT DEFAULT 0,
                country     VARCHAR(8) DEFAULT '??',
                created_at  DOUBLE NOT NULL,
                INDEX idx_ip (ip),
                INDEX idx_time (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ip_profiles (
                ip            VARCHAR(45) PRIMARY KEY,
                country       VARCHAR(8) DEFAULT '??',
                city          VARCHAR(80) DEFAULT '?',
                first_seen    DOUBLE,
                last_seen     DOUBLE,
                total_events  INT DEFAULT 0,
                max_score     INT DEFAULT 0,
                times_banned  INT DEFAULT 0
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        conn.commit()
        cur.close()
        conn.close()


# ── BAN ISLEMLERI ─────────────────────────────────────────────────────────────

def ban(ip, reason, score=0, attack_type="", country="??", city="?", duration=3600):
    """IP'yi banla. duration=0 ise kalici ban."""
    now = time.time()
    expires = None if duration == 0 else now + duration
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO banned_ips
                (ip, reason, score, attack_type, country, city, banned_at, expires_at, active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                reason=VALUES(reason), score=VALUES(score),
                attack_type=VALUES(attack_type), banned_at=VALUES(banned_at),
                expires_at=VALUES(expires_at), active=1
        """, (ip, reason, score, attack_type, country, city, now, expires))
        cur.execute(
            "UPDATE ip_profiles SET times_banned = times_banned + 1 WHERE ip = %s",
            (ip,))
        conn.commit()
        cur.close()
        conn.close()


def unban(ip):
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("UPDATE banned_ips SET active=0 WHERE ip=%s", (ip,))
        conn.commit()
        cur.close()
        conn.close()


def unban_all():
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("UPDATE banned_ips SET active=0 WHERE active=1")
        conn.commit()
        cur.close()
        conn.close()


def is_banned(ip) -> bool:
    now = time.time()
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT 1 FROM banned_ips
            WHERE ip=%s AND active=1 AND (expires_at IS NULL OR expires_at > %s)
        """, (ip, now))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row is not None


def get_active_bans() -> list:
    now = time.time()
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM banned_ips
            WHERE active=1 AND (expires_at IS NULL OR expires_at > %s)
            ORDER BY banned_at DESC
        """, (now,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows


def get_ban_history(limit=100) -> list:
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM banned_ips ORDER BY banned_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows


def cleanup_expired():
    now = time.time()
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("""
            UPDATE banned_ips SET active=0
            WHERE active=1 AND expires_at IS NOT NULL AND expires_at <= %s
        """, (now,))
        conn.commit()
        cur.close()
        conn.close()


# ── OLAY ISLEMLERI ────────────────────────────────────────────────────────────

def log_event(ip, attack_type, detail="", score=0, country="??"):
    now = time.time()
    with _lock:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (ip, attack_type, detail, score, country, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (ip, attack_type, detail, score, country, now))
        cur.execute("""
            INSERT INTO ip_profiles
                (ip, country, first_seen, last_seen, total_events, max_score)
            VALUES (%s, %s, %s, %s, 1, %s)
            ON DUPLICATE KEY UPDATE
                last_seen=VALUES(last_seen),
                total_events=total_events + 1,
                max_score=GREATEST(max_score, VALUES(max_score))
        """, (ip, country, now, now, score))
        conn.commit()
        cur.close()
        conn.close()


def get_recent_events(limit=50) -> list:
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM events ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows


def get_events_by_ip(ip) -> list:
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM events WHERE ip=%s ORDER BY created_at DESC", (ip,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows


def get_ip_profiles(limit=100) -> list:
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM ip_profiles ORDER BY total_events DESC LIMIT %s",
            (limit,))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows


def get_stats() -> dict:
    now = time.time()
    day_ago = now - 86400
    with _lock:
        conn = _conn()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT COUNT(*) c FROM events")
        total_events = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM banned_ips WHERE active=1")
        total_bans = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM ip_profiles")
        unique_ips = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM events WHERE created_at > %s", (day_ago,))
        events_24h = cur.fetchone()["c"]

        cur.execute("SELECT attack_type, COUNT(*) c FROM events GROUP BY attack_type")
        by_type = {r["attack_type"]: r["c"] for r in cur.fetchall()}

        cur.execute("""
            SELECT country, COUNT(*) c FROM events
            GROUP BY country ORDER BY c DESC LIMIT 10
        """)
        by_country = {r["country"]: r["c"] for r in cur.fetchall()}

        cur.close()
        conn.close()
        return {
            "total_events": total_events,
            "total_bans": total_bans,
            "unique_ips": unique_ips,
            "events_24h": events_24h,
            "by_type": by_type,
            "by_country": by_country,
        }
