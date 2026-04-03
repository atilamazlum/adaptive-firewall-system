const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const { execSync } = require("child_process");

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, "access.log");

app.use(cors());
app.use(express.json());

// Ban cache
const banCache = new Set();
setInterval(() => { banCache.clear(); }, 30000);

// IP temizle
function getIP(req) {
  const raw = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  return raw.replace("::ffff:", "").split(",")[0].trim();
}

// SQLite ban kontrolü
function isBanned(ip) {
  if (banCache.has(ip)) return true;
  try {
    const result = execSync(
      `python3 -c "import sys; sys.path.insert(0,'${process.env.HOME}/firewall-v2'); import db; print(db.is_banned('${ip}'))"`,
      { timeout: 1000 }
    ).toString().trim();
    if (result === "True") { banCache.add(ip); return true; }
    return false;
  } catch { return false; }
}

// Ban middleware — her istekte çalışır
app.use((req, res, next) => {
  const ip = getIP(req);
  if (isBanned(ip)) {
    console.log(`[BLOCKED] ${ip} → banlı IP erişim engellendi`);
    return res.status(403).sendFile(path.join(__dirname, "public", "banned.html"));
  }
  next();
});

// Log yaz
function writeLog(ip, type, detail = "") {
  const now = new Date();
  const month = now.toLocaleString("en-US", { month: "short" });
  const day = String(now.getDate()).padStart(2, " ");
  const time = now.toTimeString().split(" ")[0];
  let line = "";

  if (type === "brute_force") {
    line = `${month} ${day} ${time} server sshd[9999]: Failed password for ${detail} from ${ip} port ${Math.floor(Math.random()*60000)+1024} ssh2`;
  } else if (type === "flood") {
    line = `${month} ${day} ${time} server sshd[9999]: Did not receive identification string from ${ip}`;
  }

  if (line) {
    fs.appendFileSync(LOG_FILE, line + "\n");
    console.log(`[LOG] ${line}`);
  }
}

const USERS = [
  { username: "admin", password: "admin123" },
  { username: "user",  password: "password" },
];

const requestCounts = {};
function track(ip) {
  const now = Date.now();
  if (!requestCounts[ip]) requestCounts[ip] = [];
  requestCounts[ip].push(now);
  requestCounts[ip] = requestCounts[ip].filter(t => now - t < 60000);
  return requestCounts[ip].length;
}

app.post("/api/login", (req, res) => {
  const ip = getIP(req);
  const { username, password } = req.body;
  const count = track(ip);
  const user = USERS.find(u => u.username === username && u.password === password);

  if (!user) {
    writeLog(ip, "brute_force", username || "unknown");
    return res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı", attempts: count });
  }

  res.json({ success: true, user: { username: user.username } });
});

app.post("/api/ping", (req, res) => {
  const ip = getIP(req);
  const count = track(ip);
  if (count > 20) writeLog(ip, "flood");
  res.json({ pong: true, count });
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🎯 Target Site → http://localhost:${PORT}`);
  console.log(`📝 Log → ${LOG_FILE}\n`);
});

// IPv6 ban kontrolü ekstra
app.use((req, res, next) => {
  const raw = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ip = raw.split(",")[0].trim();
  if (isBanned(ip)) {
    return res.status(403).sendFile(path.join(__dirname, "public", "banned.html"));
  }
  next();
});
