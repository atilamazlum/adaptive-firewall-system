"""
3LayerFirewall — Giriş Noktası

Kullanım:
  sudo python3 main.py                    # Canlı mod
  sudo python3 main.py --dry-run          # Test modu
  sudo python3 main.py --simulate         # Simülasyon
  sudo python3 main.py --setup            # nftables kur
"""

import argparse
import threading
import time
import random
import tempfile
from engine import FirewallEngine
import nftables
import banner

parser = argparse.ArgumentParser(description="3LayerFirewall")
parser.add_argument("--dry-run",  action="store_true")
parser.add_argument("--simulate", action="store_true")
parser.add_argument("--setup",    action="store_true")
parser.add_argument("--log-path", default="/var/log/auth.log")
args = parser.parse_args()

FAKE_LOGS = [
    "Mar 29 03:14:22 server sshd[1234]: Failed password for root from {ip} port 54321 ssh2",
    "Mar 29 03:14:23 server sshd[1234]: Failed password for admin from {ip} port 54322 ssh2",
    "Mar 29 03:14:24 server sshd[1234]: Invalid user test from {ip}",
    "Mar 29 03:14:25 server sshd[1234]: Failed password for invalid user ubuntu from {ip} port 54323 ssh2",
    "Mar 29 03:14:26 server sshd[1234]: error: maximum authentication attempts exceeded for root from {ip} port 54320 ssh2 [preauth]",
    "Mar 29 03:14:27 server sshd[1234]: Connection closed by {ip} port 80",
    "Mar 29 03:14:28 server sshd[1234]: Connection closed by {ip} port 443",
    "Mar 29 03:14:29 server sshd[1234]: Connection closed by {ip} port 8080",
    "Mar 29 03:14:30 server sshd[1234]: Did not receive identification string from {ip}",
    "Mar 29 03:14:31 server sshd[1234]: Did not receive identification string from {ip}",
    "Mar 29 03:14:32 server sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}",
]

ATTACK_IPS = [
    "185.220.101.45",  # Rusya
    "45.155.205.10",   # Hollanda
    "103.149.28.50",   # Çin
    "23.129.64.131",   # ABD
]

def simulate(log_path):
    time.sleep(1)
    print(f"\n[SİMÜLASYON] Saldırı logları yazılıyor...\n")
    with open(log_path, "a") as f:
        for i in range(100):
            ip = random.choice(ATTACK_IPS)
            line = random.choice(FAKE_LOGS).format(ip=ip)
            f.write(line + "\n")
            f.flush()
            time.sleep(0.1)
    print("\n[SİMÜLASYON] Tamamlandı.")

def main():
    if args.setup:
        ok, msg = nftables.setup()
        print(f"nftables: {msg}")
        return

    if args.simulate:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                          prefix="3lf_", delete=False)
        tmp.close()
        log_path = tmp.name
        t = threading.Thread(target=simulate, args=(log_path,), daemon=True)
        t.start()
        engine = FirewallEngine(log_path=log_path, dry_run=False)
    else:
        engine = FirewallEngine(log_path=args.log_path, dry_run=args.dry_run)

    engine.run()

if __name__ == "__main__":
    main()
