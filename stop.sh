#!/bin/bash
# Adaptive Firewall System — Durdurma Scripti

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

RED='\033[91m'; GREEN='\033[92m'; RESET='\033[0m'

echo ""
echo "Servisler durduruluyor..."

# PID dosyasindan
if [ -f .pids ]; then
    for pid in $(cat .pids); do
        kill "$pid" 2>/dev/null && echo -e "  ${GREEN}durduruldu${RESET} PID $pid"
    done
    rm -f .pids
fi

# Yedek — isimle oldur
pkill -f "main.py --log" 2>/dev/null
pkill -f "site/server.js" 2>/dev/null
pkill -f "dashboard/server.js" 2>/dev/null

echo -e "${RED}Tum servisler durduruldu.${RESET}"
echo ""
