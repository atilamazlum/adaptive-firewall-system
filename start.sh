#!/bin/bash
# Adaptive Firewall System — Baslatma Scripti
# Tum bilesenleri arka planda baslatir.

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[92m'; BLUE='\033[94m'; YELLOW='\033[93m'; RESET='\033[0m'

echo ""
echo -e "${BLUE}========================================${RESET}"
echo -e "${BLUE}  ADAPTIVE FIREWALL SYSTEM${RESET}"
echo -e "${BLUE}========================================${RESET}"
echo ""

# Log klasoru
mkdir -p logs
touch site/access.log

# ── 1. Hedef Site ──────────────────────────────────────────
echo -e "${YELLOW}[1/3]${RESET} Hedef site baslatiliyor..."
cd site
node server.js > "$PROJECT_DIR/logs/site.log" 2>&1 &
SITE_PID=$!
cd "$PROJECT_DIR"
echo -e "      ${GREEN}OK${RESET} (PID: $SITE_PID) -> http://localhost:3000"

sleep 1

# ── 2. Guvenlik Duvari ─────────────────────────────────────
echo -e "${YELLOW}[2/3]${RESET} Guvenlik duvari baslatiliyor..."
if [ "$EUID" -eq 0 ]; then
    python3 main.py --log site/access.log > "$PROJECT_DIR/logs/firewall.log" 2>&1 &
    FW_PID=$!
    echo -e "      ${GREEN}OK${RESET} (PID: $FW_PID) - CANLI mod (nftables aktif)"
else
    python3 main.py --dry-run --log site/access.log > "$PROJECT_DIR/logs/firewall.log" 2>&1 &
    FW_PID=$!
    echo -e "      ${GREEN}OK${RESET} (PID: $FW_PID) - DRY-RUN mod (root degil)"
fi

sleep 1

# ── 3. Dashboard ───────────────────────────────────────────
echo -e "${YELLOW}[3/3]${RESET} Dashboard baslatiliyor..."
cd dashboard
node server.js > "$PROJECT_DIR/logs/dashboard.log" 2>&1 &
DASH_PID=$!
cd "$PROJECT_DIR"
echo -e "      ${GREEN}OK${RESET} (PID: $DASH_PID) -> http://localhost:4000"

# PID'leri kaydet
echo "$SITE_PID $FW_PID $DASH_PID" > "$PROJECT_DIR/.pids"

echo ""
echo -e "${GREEN}========================================${RESET}"
echo -e "${GREEN}  TUM SERVISLER CALISIYOR${RESET}"
echo -e "${GREEN}========================================${RESET}"
echo ""
echo -e "  Hedef Site   ${BLUE}http://localhost:3000${RESET}"
echo -e "  Dashboard    ${BLUE}http://localhost:4000${RESET}"
echo ""
echo -e "  Loglar:      logs/ klasoru"
echo -e "  Saldiri test: python3 simulator/attack_sim.py"
echo -e "  Durdurmak:    bash stop.sh"
echo ""
