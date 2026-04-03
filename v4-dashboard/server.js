const express = require("express");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const app = express();
const PORT = 4000;
const DB_PATH = process.env.DB_PATH || `${process.env.HOME}/firewall-v2/bans.db`;
const LOG_PATH = process.env.LOG_PATH || `${process.env.HOME}/target-site/access.log`;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function getDB() {
  try { return new Database(DB_PATH); } catch { return null; }
}

// IP'den ülke al
async function getCountry(ip) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,city,org,lat,lon`);
    return await res.json();
  } catch { return { country: "Unknown", countryCode: "??", city: "?", lat: 0, lon: 0 }; }
}

// Log parse
function parseLogs() {
  try {
    if (!fs.existsSync(LOG_PATH)) return [];
    const lines = fs.readFileSync(LOG_PATH, "utf8").split("\n").filter(Boolean);
    return lines.map(line => line).filter(Boolean);
  }
  catch { return []; }
}

function parseLogs2() {
  try {
    if (!fs.existsSync(LOG_PATH)) return [];
    const lines = fs.readFileSync(LOG_PATH, "utf8").split("\n").filter(Boolean);
    return lines.map(line => {
      const ipMatch = line.match(/from ([\d.]+)/);
      const userMatch = line.match(/for (\S+) from/);
      let type = "unknown";
      if (line.includes("Failed password")) type = "brute_force";
      else if (line.includes("identification string")) type = "flood";
      else if (line.includes("XSS")) type = "xss";
      else if (line.includes("SQL")) type = "sqli";
      const timeMatch = line.match(/(\w+ \d+ \d+:\d+:\d+)/);
      return {
        ip: ipMatch ? ipMatch[1] : null,
        user: userMatch ? userMatch[1] : null,
        type,
        time: timeMatch ? timeMatch[1] : null,
        raw: line,
        ts: fs.statSync ? Date.now() : Date.now()
      };
    }).filter(l => l.ip);
  } catch { return []; }
}

function getIPStats() {
  const logs = parseLogs();
  const stats = {};
  logs.forEach(l => {
    if (!stats[l.ip]) stats[l.ip] = { brute_force:0, flood:0, xss:0, sqli:0, total:0, lastSeen: l.time, events: [] };
    stats[l.ip].total++;
    stats[l.ip][l.type] = (stats[l.ip][l.type] || 0) + 1;
    stats[l.ip].events.push(l);
  });
  return stats;
}

function getHourlyStats() {
  const logs = parseLogs();
  const hours = {};
  logs.forEach(l => {
    const h = l.time ? l.time.split(" ").slice(-1)[0].split(":")[0] : "00";
    if (!hours[h]) hours[h] = { brute_force:0, flood:0, xss:0, sqli:0, total:0 };
    hours[h].total++;
    hours[h][l.type] = (hours[h][l.type] || 0) + 1;
  });
  return hours;
}

// API routes
app.get("/api/status", (req, res) => {
  const db = getDB();
  let banned = [], totalBanned = 0;
  if (db) {
    const now = Date.now() / 1000;
    banned = db.prepare("SELECT * FROM banned_ips WHERE expires_at IS NULL OR expires_at > ? ORDER BY banned_at DESC").all(now);
    totalBanned = banned.length;
    db.close();
  }

  const ipStats = getIPStats();
  const hourly = getHourlyStats();
  const logs = parseLogs();
  const recentLogs = logs.slice(-30).reverse().map(l => l.raw || l);
  const total = logs.length;

  const typeCounts = { brute_force:0, flood:0, xss:0, sqli:0 };
  logs.forEach(l => { if (typeCounts[l.type] !== undefined) typeCounts[l.type]++; });

  res.json({ banned, totalBanned, ipStats, hourly, recentLogs, total, typeCounts, timestamp: new Date().toISOString() });
});

app.get("/api/history", (req, res) => {
  const db = getDB();
  if (!db) return res.json({ history: [] });
  try {
    const history = db.prepare("SELECT * FROM banned_ips ORDER BY banned_at DESC LIMIT 100").all();
    db.close();
    res.json({ history });
  } catch { res.json({ history: [] }); }
});

app.post("/api/ban", (req, res) => {
  const { ip } = req.body;
  const db = getDB();
  if (!db) return res.status(500).json({ success: false });
  try {
    const now = Date.now() / 1000;
    db.prepare("INSERT OR REPLACE INTO banned_ips (ip, reason, score, country, city, banned_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(ip, "manual", 100, "??", "?", now, now + 3600);
    db.close();
    res.json({ success: true });
  } catch { res.status(500).json({ success: false }); }
});

app.post("/api/unban", (req, res) => {
  const { ip } = req.body;
  const db = getDB();
  if (!db) return res.status(500).json({ success: false });
  try {
    db.prepare("DELETE FROM banned_ips WHERE ip = ?").run(ip);
    db.close();
    res.json({ success: true });
  } catch { res.status(500).json({ success: false }); }
});

app.post("/api/unban-all", (req, res) => {
  const db = getDB();
  if (!db) return res.status(500).json({ success: false });
  try {
    db.prepare("DELETE FROM banned_ips").run();
    db.close();
    res.json({ success: true });
  } catch { res.status(500).json({ success: false }); }
});

app.post("/api/telegram", async (req, res) => {
  const { token, chatId, message } = req.body;
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: "HTML" })
    });
    const data = await r.json();
    res.json({ success: data.ok });
  } catch { res.status(500).json({ success: false }); }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n📊 V4 Dashboard → http://localhost:${PORT}\n`);
});
