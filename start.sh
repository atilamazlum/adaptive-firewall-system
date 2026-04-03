#!/bin/bash
echo "🛡 3LayerFirewall başlatılıyor..."

touch ~/target-site/access.log

# Arka planda başlat
python3 ~/firewall-v2/main.py --log-path ~/target-site/access.log > ~/firewall-project/firewall.log 2>&1 &
echo "✅ Firewall başladı (PID: $!)"

node ~/target-site/server.js > ~/firewall-project/target.log 2>&1 &
echo "✅ Target site başladı (PID: $!)"

LOG_PATH=~/target-site/access.log node ~/v4-dashboard/server.js > ~/firewall-project/dashboard.log 2>&1 &
echo "✅ Dashboard başladı (PID: $!)"

echo ""
echo "🎯 Site      → http://localhost:3000"
echo "📊 Dashboard → http://localhost:4000"
echo ""
echo "Logları görmek için:"
echo "  tail -f ~/firewall-project/firewall.log"
echo "  tail -f ~/firewall-project/target.log"
echo ""
echo "Durdurmak için: bash ~/firewall-project/stop.sh"
