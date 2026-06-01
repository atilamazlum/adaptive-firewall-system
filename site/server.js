/**
 * Adaptive Firewall — Hedef Site (Target Site)
 * MySQL surumu.
 *
 * Kasitli savunmasiz test sitesi. Tum saldiri turlerini access.log'a yazar.
 */

const express = require("express");
const path = require("path");
const fs = require("fs");
const mysql = require("mysql2/promise");

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_PATH = process.env.LOG_PATH || path.join(__dirname, "access.log");

const DB_CONFIG = {
  host: "localhost",
  port: 3306,
  user: "fwuser",
  password: "firewall123",
  database: "firewall",
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── MYSQL BAGLANTI HAVUZU ───────────────────────────────────────────────────
let pool;
async function initDB() {
  pool = mysql.createPool({ ...DB_CONFIG, waitForConnections: true, connectionLimit: 5 });
  // Site kullanicilari tablosu
  await pool.query(`
    CREATE TABLE IF NOT EXISTS site_users (
      id INT PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(80) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at BIGINT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  const [rows] = await pool.query("SELECT COUNT(*) c FROM site_users");
  if (rows[0].c === 0) {
    await pool.query(
      "INSERT INTO site_users (username, password, created_at) VALUES (?, ?, ?)",
      ["admin", "admin123", Date.now()]
    );
  }
}

// ─── YARDIMCILAR ─────────────────────────────────────────────────────────────
function getIP(req) {
  const raw = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  return raw.replace("::ffff:", "").split(",")[0].trim();
}

function writeLog(line) {
  const ts = new Date().toISOString();
  fs.appendFileSync(LOG_PATH, `${line}\n`);
  console.log(`[${ts}] ${line}`);
}

async function isBanned(ip) {
  try {
    const now = Date.now() / 1000;
    const [rows] = await pool.query(
      `SELECT 1 FROM banned_ips
       WHERE ip=? AND active=1 AND (expires_at IS NULL OR expires_at > ?)`,
      [ip, now]
    );
    return rows.length > 0;
  } catch {
    return false;
  }
}

// ─── BAN MIDDLEWARE — static'ten ONCE calismali! ─────────────────────────────
app.use(async (req, res, next) => {
  const ip = getIP(req);
  if (await isBanned(ip)) {
    return res.status(403).sendFile(path.join(__dirname, "public", "banned.html"));
  }
  next();
});

// Statik dosyalar — ban kontrolunden SONRA
app.use(express.static(path.join(__dirname, "public")));

// ─── SALDIRI TESPIT YARDIMCILARI ─────────────────────────────────────────────
const reSQLi = /(union\s+select|or\s+1=1|';\s*drop|--\s|\/\*|sleep\(|benchmark\()/i;
const reXSS = /(<script|javascript:|onerror=|onload=|<img[^>]+src|%3Cscript|<svg)/i;
const rePath = /(\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|c:\\windows)/i;
const reCmd = /(;\s*(cat|ls|wget|curl|rm|nc)\s|\|\s*(bash|sh)|`.*`|\$\(.*\))/i;
const reBot = /(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|hydra|wpscan)/i;

// Bot tespiti
app.use((req, res, next) => {
  const ua = req.headers["user-agent"] || "";
  if (reBot.test(ua)) writeLog(`BAD_BOT ip=${getIP(req)} agent=${ua}`);
  next();
});

// ─── HONEYPOT ────────────────────────────────────────────────────────────────
["/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env",
 "/.git/config", "/admin.php", "/administrator"].forEach(hp => {
  app.all(hp, (req, res) => {
    writeLog(`HONEYPOT ip=${getIP(req)} path=${hp}`);
    res.status(404).send("Not Found");
  });
});

// ─── API: LOGIN ──────────────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const ip = getIP(req);
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query(
      "SELECT * FROM site_users WHERE username=?", [username || ""]);
    const user = rows[0];
    if (!user || user.password !== password) {
      writeLog(`LOGIN_FAIL ip=${ip} user=${username || "unknown"}`);
      return res.status(401).json({ ok: false, error: "Kullanici adi veya sifre hatali" });
    }
    res.json({ ok: true, message: "Giris basarili", username: user.username });
  } catch {
    res.status(500).json({ ok: false, error: "Sunucu hatasi" });
  }
});

// ─── API: SIGNUP ─────────────────────────────────────────────────────────────
app.post("/api/signup", async (req, res) => {
  const ip = getIP(req);
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "Tum alanlar zorunlu" });
  }
  if (username.length < 3 || password.length < 4) {
    return res.status(400).json({ ok: false, error: "Kullanici adi en az 3, sifre en az 4 karakter" });
  }
  try {
    await pool.query(
      "INSERT INTO site_users (username, password, created_at) VALUES (?, ?, ?)",
      [username, password, Date.now()]);
    writeLog(`SIGNUP ip=${ip} user=${username}`);
    res.json({ ok: true, message: "Kayit basarili" });
  } catch {
    res.status(409).json({ ok: false, error: "Bu kullanici adi zaten alinmis" });
  }
});

// ─── API: SEARCH (SQLi) ──────────────────────────────────────────────────────
app.get("/api/search", (req, res) => {
  const ip = getIP(req);
  const q = req.query.q || "";
  if (reSQLi.test(q)) {
    writeLog(`SQLI_ATTEMPT ip=${ip} payload=${q}`);
    return res.status(400).json({ ok: false, error: "Gecersiz arama" });
  }
  const results = ["Havale islemi - 1500 TL", "Fatura odemesi - 240 TL"]
    .filter(r => r.toLowerCase().includes(q.toLowerCase()));
  res.json({ ok: true, query: q, results });
});

// ─── API: COMMENT (XSS) ──────────────────────────────────────────────────────
const comments = [];
app.post("/api/comment", (req, res) => {
  const ip = getIP(req);
  const text = req.body.text || "";
  if (reXSS.test(text)) {
    writeLog(`XSS_ATTEMPT ip=${ip} payload=${text}`);
    return res.status(400).json({ ok: false, error: "Yorum reddedildi" });
  }
  if (reCmd.test(text)) {
    writeLog(`CMD_INJECT ip=${ip} cmd=${text}`);
    return res.status(400).json({ ok: false, error: "Yorum reddedildi" });
  }
  comments.push({ text, time: Date.now() });
  res.json({ ok: true, comments: comments.slice(-10) });
});

app.get("/api/comments", (req, res) => {
  res.json({ ok: true, comments: comments.slice(-10) });
});

// ─── API: PROFILE (path traversal) ───────────────────────────────────────────
app.get("/api/profile", (req, res) => {
  const ip = getIP(req);
  const file = req.query.file || "default";
  if (rePath.test(file)) {
    writeLog(`PATH_TRAVERSAL ip=${ip} path=${file}`);
    return res.status(400).json({ ok: false, error: "Gecersiz dosya yolu" });
  }
  res.json({ ok: true, profile: `Profil dosyasi: ${file}` });
});

// ─── API: PING (flood) ───────────────────────────────────────────────────────
const pingTracker = {};
app.get("/api/ping", (req, res) => {
  const ip = getIP(req);
  const now = Date.now();
  if (!pingTracker[ip]) pingTracker[ip] = [];
  pingTracker[ip].push(now);
  pingTracker[ip] = pingTracker[ip].filter(t => now - t < 10000);
  const rate = pingTracker[ip].length;
  if (rate > 50) writeLog(`FLOOD ip=${ip} rate=${rate}`);
  res.json({ ok: true, pong: true, rate });
});

// ─── BASLAT ──────────────────────────────────────────────────────────────────
if (!fs.existsSync(LOG_PATH)) fs.writeFileSync(LOG_PATH, "");

initDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log("");
    console.log("  Hedef Site (Target Site) — MySQL");
    console.log(`  URL : http://localhost:${PORT}`);
    console.log(`  Log : ${LOG_PATH}`);
    console.log("");
  });
}).catch(err => {
  console.error("MySQL baglanti hatasi:", err.message);
  process.exit(1);
});
