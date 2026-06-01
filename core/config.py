"""
Adaptive Firewall — Konfigurasyon
Tum sistem ayarlari burada toplanir.
"""

import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

# Dosya yollari
LOG_PATH = os.path.join(PROJECT_DIR, "site", "access.log")
SETTINGS_PATH = os.path.join(PROJECT_DIR, "settings.json")

# ── MySQL baglanti bilgisi ───────────────────────────────────────────────────
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "fwuser",
    "password": "firewall123",
    "database": "firewall",
}

# nftables ayarlari
NFT_TABLE = "inet"
NFT_FAMILY = "filter"
NFT_BANNED_SET = "fw_banned"
NFT_GRAYLIST_SET = "fw_graylist"

# Varsayilan ayarlar
DEFAULT_SETTINGS = {
    "ban_score": 70,
    "graylist_score": 40,
    "ban_duration": 0,
    "brute_force_count": 5,
    "brute_force_window": 60,
    "slow_brute_count": 15,
    "slow_brute_window": 1800,
    "port_scan_count": 10,
    "port_scan_window": 30,
    "ddos_count": 100,
    "ddos_window": 10,
    "web_attack_count": 3,
    "web_attack_window": 60,
    "bot_count": 5,
    "bot_window": 60,
    "foreign_penalty": 20,
    "night_multiplier": 25,
    "night_start": 0,
    "night_end": 5,
    "mixed_attack_bonus": 15,
    "persistent_penalty": 10,
    "honeypot_score": 100,
    "trusted_countries": ["TR"],
}

SCORE_WEIGHTS = {
    "threshold_hit": 50,
    "high_speed": 30,
    "web_attack": 40,
    "honeypot": 100,
    "bot": 25,
}

WHITELIST = {"127.0.0.1", "::1", "localhost"}

HONEYPOT_PATHS = [
    "/admin.php", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/.git/config", "/config.php", "/shell.php",
    "/administrator", "/cgi-bin", "/.ssh/id_rsa",
]


def load_settings() -> dict:
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                saved = json.load(f)
            merged = dict(DEFAULT_SETTINGS)
            merged.update(saved)
            return merged
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)
