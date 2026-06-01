#!/usr/bin/env python3
"""
Adaptive Firewall System — Giriş Noktası

Kullanım:
  python3 main.py                  → Canlı mod (nftables ile gerçek engelleme)
  python3 main.py --dry-run        → Test modu (engelleme yok, sadece tespit)
  python3 main.py --log /path/log  → Özel log dosyası belirt

Canlı modda root yetkisi gerekir (nftables için).
"""

import sys
import os

# core/ klasörünü import yoluna ekle
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "core"))

from engine import FirewallEngine
import config


def parse_args():
    dry_run = False
    log_path = None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ("--dry-run", "-d"):
            dry_run = True
        elif args[i] in ("--log", "-l") and i + 1 < len(args):
            log_path = args[i + 1]
            i += 1
        elif args[i] in ("--help", "-h"):
            print(__doc__)
            sys.exit(0)
        i += 1
    return dry_run, log_path


def main():
    dry_run, log_path = parse_args()

    if not dry_run and os.geteuid() != 0:
        print("UYARI: Canli mod icin root yetkisi gerekir.")
        print("       'sudo python3 main.py' veya test icin '--dry-run' kullanin.\n")

    engine = FirewallEngine(log_path=log_path or config.LOG_PATH, dry_run=dry_run)
    engine.run()


if __name__ == "__main__":
    main()
