/**
 * Adaptive Firewall — Dashboard Backend (MySQL)
 * Firewall veritabanini okuyup web arayuzune sunar, WebSocket ile canli yayin.
 */

const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const path = require("path");
const fs = require("fs");
const mysql = require("mysql2/promise");
const PDFDocument = require("pdfkit");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 4000;
const PROJECT_DIR = path.join(__dirname, "..");
const SETTINGS_PATH = path.join(PROJECT_DIR, "settings.json");
const TELEGRAM_PATH = path.join(PROJECT_DIR, ".telegram");

const DB_CONFIG = {
  host: "localhost", port: 3306,
  user: "fwuser", password: "firewall123", database: "firewall",
};

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let pool;

// ─── AYARLAR ─────────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  ban_score: 70, graylist_score: 40, ban_duration: 3600,
  brute_force_count: 5, brute_force_window: 60,
  slow_brute_count: 15, slow_brute_window: 1800,
  port_scan_count: 10, port_scan_window: 30,
  ddos_count: 100, ddos_window: 10,
  web_attack_count: 3, web_attack_window: 60,
  bot_count: 5, bot_window: 60,
  foreign_penalty: 20, night_multiplier: 25,
  night_start: 0, night_end: 5,
  mixed_attack_bonus: 15, persistent_penalty: 10,
  honeypot_score: 100, trusted_countries: ["TR"],
};

function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_PATH)) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8")) };
    }
  } catch {}
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(s) {
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(s, null, 2));
}

// ─── VERI TOPLAMA ────────────────────────────────────────────────────────────
async function getDashboardData() {
  try {
    const now = Date.now() / 1000;
    const dayAgo = now - 86400;

    const [banned] = await pool.query(
      `SELECT * FROM banned_ips
       WHERE active=1 AND (expires_at IS NULL OR expires_at > ?)
       ORDER BY banned_at DESC`, [now]);

    const [events] = await pool.query(
      "SELECT * FROM events ORDER BY created_at DESC LIMIT 40");

    const [profiles] = await pool.query(
      "SELECT * FROM ip_profiles ORDER BY total_events DESC LIMIT 20");

    const [[te]] = await pool.query("SELECT COUNT(*) c FROM events");
    const [[tb]] = await pool.query("SELECT COUNT(*) c FROM banned_ips WHERE active=1");
    const [[ui]] = await pool.query("SELECT COUNT(*) c FROM ip_profiles");
    const [[e24]] = await pool.query(
      "SELECT COUNT(*) c FROM events WHERE created_at > ?", [dayAgo]);

    const [typeRows] = await pool.query(
      "SELECT attack_type, COUNT(*) c FROM events GROUP BY attack_type");
    const by_type = {};
    typeRows.forEach(r => { by_type[r.attack_type] = r.c; });

    const [hourRows] = await pool.query(
      "SELECT created_at FROM events WHERE created_at > ?", [dayAgo]);
    const hourly = Array(24).fill(0);
    hourRows.forEach(r => {
      const h = new Date(r.created_at * 1000).getHours();
      hourly[h]++;
    });

    return {
      ok: true, banned, events, profiles,
      stats: {
        total_events: te.c, total_bans: tb.c,
        unique_ips: ui.c, events_24h: e24.c,
        by_type, hourly,
      },
      settings: loadSettings(),
    };
  } catch (err) {
    console.error("DB hata:", err.message);
    return { ok: false, banned: [], events: [], profiles: [], stats: {}, settings: loadSettings() };
  }
}

// ─── WEBSOCKET ───────────────────────────────────────────────────────────────
async function broadcast() {
  const data = JSON.stringify({ type: "update", data: await getDashboardData() });
  wss.clients.forEach(c => { if (c.readyState === 1) c.send(data); });
}

wss.on("connection", async (ws) => {
  ws.send(JSON.stringify({ type: "update", data: await getDashboardData() }));
});

// Periyodik yayin (her 2 saniye)
setInterval(broadcast, 2000);

// ─── API ─────────────────────────────────────────────────────────────────────
app.get("/api/dashboard", async (req, res) => res.json(await getDashboardData()));

app.get("/api/history", async (req, res) => {
  try {
    const [history] = await pool.query(
      "SELECT * FROM banned_ips ORDER BY banned_at DESC LIMIT 100");
    res.json({ history });
  } catch { res.json({ history: [] }); }
});

app.get("/api/ip/:ip", async (req, res) => {
  try {
    const [events] = await pool.query(
      "SELECT * FROM events WHERE ip=? ORDER BY created_at DESC", [req.params.ip]);
    const [profileRows] = await pool.query(
      "SELECT * FROM ip_profiles WHERE ip=?", [req.params.ip]);
    res.json({ events, profile: profileRows[0] || {} });
  } catch { res.json({ events: [], profile: {} }); }
});

app.get("/api/settings", (req, res) => res.json(loadSettings()));

app.post("/api/settings", (req, res) => {
  try {
    const updated = { ...loadSettings(), ...req.body };
    saveSettings(updated);
    broadcast();
    res.json({ ok: true, settings: updated });
  } catch { res.status(500).json({ ok: false }); }
});

app.post("/api/unban", async (req, res) => {
  try {
    await pool.query("UPDATE banned_ips SET active=0 WHERE ip=?", [req.body.ip]);
    broadcast();
    res.json({ ok: true });
  } catch { res.status(500).json({ ok: false }); }
});

app.post("/api/unban-all", async (req, res) => {
  try {
    await pool.query("UPDATE banned_ips SET active=0 WHERE active=1");
    broadcast();
    res.json({ ok: true });
  } catch { res.status(500).json({ ok: false }); }
});

app.post("/api/ban", async (req, res) => {
  try {
    const now = Date.now() / 1000;
    const s = loadSettings();
    const expires = s.ban_duration > 0 ? now + s.ban_duration : null;
    await pool.query(`
      INSERT INTO banned_ips
        (ip, reason, score, attack_type, country, city, banned_at, expires_at, active)
      VALUES (?, 'manuel', 100, 'manual', '??', '?', ?, ?, 1)
      ON DUPLICATE KEY UPDATE active=1, banned_at=VALUES(banned_at), expires_at=VALUES(expires_at)
    `, [req.body.ip, now, expires]);
    broadcast();
    res.json({ ok: true });
  } catch { res.status(500).json({ ok: false }); }
});

app.post("/api/telegram", async (req, res) => {
  const { token, chatId, message } = req.body;
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message }),
    });
    const data = await r.json();
    if (data.ok) fs.writeFileSync(TELEGRAM_PATH, `${token}\n${chatId}`);
    res.json({ ok: data.ok });
  } catch { res.status(500).json({ ok: false }); }
});

// ─── BASLAT ──────────────────────────────────────────────────────────────────



app.get("/api/report", async (req, res) => {
  try {
    const now = Date.now() / 1000;
    const weekAgo = now - 604800;
    const monthAgo = now - 2592000;
    const [banned] = await pool.query("SELECT * FROM banned_ips ORDER BY banned_at DESC LIMIT 50");
    const [[totalEvents]] = await pool.query("SELECT COUNT(*) c FROM events");
    const [[totalBans]] = await pool.query("SELECT COUNT(*) c FROM banned_ips WHERE active=1");
    const [[uniqueIps]] = await pool.query("SELECT COUNT(*) c FROM ip_profiles");
    const [[events7d]] = await pool.query("SELECT COUNT(*) c FROM events WHERE created_at > ?", [weekAgo]);
    const [[events30d]] = await pool.query("SELECT COUNT(*) c FROM events WHERE created_at > ?", [monthAgo]);
    const [byType] = await pool.query("SELECT attack_type, COUNT(*) c FROM events GROUP BY attack_type ORDER BY c DESC");
    const [byCountry] = await pool.query("SELECT country, COUNT(*) c FROM events GROUP BY country ORDER BY c DESC LIMIT 10");
    const [topIps] = await pool.query("SELECT ip, country, total_events, max_score, times_banned FROM ip_profiles ORDER BY total_events DESC LIMIT 12");

    const doc = new PDFDocument({ size: "A4", margin: 0 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=\"firewall-rapor-" + new Date().toISOString().slice(0,10) + ".pdf\"");
    doc.pipe(res);

    const NAVY="#0a2540", GOLD="#c9a44c", LINE="#e2e8f0";
    const TEXT="#0a2540", TEXT2="#5a6b7d", TEXT3="#9aa7b5";
    const RED="#d4332a", ORANGE="#d97706", GREEN="#1a9e62";
    const PURPLE="#7c3aed", BLUE="#2563eb", TEAL="#0891b2", PINK="#db2777", LIME="#65a30d";
    const W=595, H=842, M=40;

    doc.rect(0,0,W,130).fill(NAVY);
    doc.circle(M+18,65,18).fillAndStroke(GOLD,GOLD);
    doc.fillColor(NAVY).fontSize(20).font("Helvetica-Bold").text("A",M+12,55);
    doc.fillColor("#ffffff").fontSize(22).font("Helvetica-Bold").text("ADAPTIVE FIREWALL",M+50,42);
    doc.fillColor(GOLD).fontSize(11).font("Helvetica").text("Guvenlik Raporu  -  v3.0",M+50,70);
    doc.fillColor("#aaaaaa").fontSize(9).text(new Date().toLocaleString("tr-TR"),M+50,88);
    doc.fillColor(GOLD).fontSize(9).font("Helvetica-Bold").text("RAPOR TARIHI",W-M-100,50,{width:100,align:"right"});
    doc.fillColor("#ffffff").fontSize(14).font("Helvetica-Bold").text(new Date().toLocaleDateString("tr-TR"),W-M-100,65,{width:100,align:"right"});
    doc.fillColor("#aaaaaa").fontSize(8).font("Helvetica").text("Son 30 gun",W-M-100,86,{width:100,align:"right"});

    let y=160;
    doc.fillColor(NAVY).fontSize(11).font("Helvetica-Bold").text("OZET METRIKLER",M,y);
    doc.strokeColor(GOLD).lineWidth(2).moveTo(M,y+16).lineTo(M+80,y+16).stroke();
    y+=28;

    const metrics=[
      {label:"Toplam Olay",value:totalEvents.c,color:BLUE},
      {label:"Aktif Ban",value:totalBans.c,color:RED},
      {label:"Izlenen IP",value:uniqueIps.c,color:TEAL},
      {label:"Son 7 Gun",value:events7d.c,color:PURPLE},
      {label:"Son 30 Gun",value:events30d.c,color:ORANGE}
    ];
    const mw=(W-2*M-32)/5;
    metrics.forEach((m,i)=>{
      const x=M+i*(mw+8);
      doc.rect(x,y,mw,56).fillAndStroke("#f7f9fb",LINE);
      doc.rect(x,y,3,56).fill(m.color);
      doc.fillColor(TEXT2).fontSize(8).font("Helvetica").text(m.label.toUpperCase(),x+10,y+8,{width:mw-14});
      doc.fillColor(NAVY).fontSize(18).font("Helvetica-Bold").text(String(m.value),x+10,y+22,{width:mw-14});
    });
    y+=76;

    doc.fillColor(NAVY).fontSize(11).font("Helvetica-Bold").text("SALDIRI TURU DAGILIMI",M,y);
    doc.strokeColor(GOLD).lineWidth(2).moveTo(M,y+16).lineTo(M+80,y+16).stroke();
    y+=26;

    const typeColors={brute_force:RED,ddos:ORANGE,xss:BLUE,sqli:PURPLE,path_traversal:TEAL,command_injection:PINK,bot:TEXT3,honeypot:NAVY,port_scan:GREEN,mixed:LIME};
    const chartX=M+130, chartW=W-M-chartX-20;
    const maxT=Math.max.apply(null,byType.map(r=>r.c).concat([1]));

    byType.slice(0,9).forEach(row=>{
      const w=(row.c/maxT)*chartW;
      const color=typeColors[row.attack_type]||TEXT3;
      doc.fillColor(TEXT).fontSize(9).font("Helvetica-Bold").text(row.attack_type.toUpperCase(),M,y+3,{width:125,align:"right"});
      doc.rect(chartX,y,chartW,16).fillAndStroke("#f0f3f7","#f0f3f7");
      doc.rect(chartX,y,w,16).fill(color);
      doc.fillColor(TEXT).fontSize(9).font("Helvetica-Bold").text(String(row.c),chartX+w+6,y+3);
      y+=25;
    });
    y+=12;

    doc.fillColor(NAVY).fontSize(11).font("Helvetica-Bold").text("EN COK SALDIRI ALINAN ULKELER",M,y);
    doc.strokeColor(GOLD).lineWidth(2).moveTo(M,y+16).lineTo(M+80,y+16).stroke();
    y+=26;

    const colW=(W-2*M-14)/2;
    const half=Math.ceil(byCountry.length/2);
    byCountry.forEach((row,i)=>{
      const col=i<half?0:1;
      const idx=i<half?i:i-half;
      const x=M+col*(colW+14);
      const ry=y+idx*22;
      doc.rect(x,ry,colW,20).fillAndStroke("#fafbfc",LINE);
      doc.fillColor(GOLD).fontSize(9).font("Helvetica-Bold").text(String(i+1).padStart(2,"0"),x+8,ry+6);
      doc.fillColor(TEXT).fontSize(10).font("Helvetica-Bold").text(row.country||"??",x+30,ry+5);
      doc.fillColor(TEXT2).fontSize(9).font("Helvetica").text(row.c+" olay",x+colW-70,ry+6,{width:60,align:"right"});
    });
    y+=half*22+14;

    doc.addPage();
    doc.rect(0,0,W,50).fill(NAVY);
    doc.fillColor("#ffffff").fontSize(14).font("Helvetica-Bold").text("ADAPTIVE FIREWALL - SAYFA 2",M,18);
    doc.fillColor(GOLD).fontSize(8).font("Helvetica").text("Detayli Analiz",M,36);
    y=80;

    doc.fillColor(NAVY).fontSize(11).font("Helvetica-Bold").text("EN AKTIF IP ADRESLERI",M,y);
    doc.strokeColor(GOLD).lineWidth(2).moveTo(M,y+16).lineTo(M+80,y+16).stroke();
    y+=26;

    doc.rect(M,y,W-2*M,22).fill(NAVY);
    doc.fillColor("#ffffff").fontSize(9).font("Helvetica-Bold");
    doc.text("IP ADRESI",M+10,y+7);
    doc.text("ULKE",M+200,y+7);
    doc.text("OLAY",M+260,y+7);
    doc.text("MAKS SKOR",M+320,y+7);
    doc.text("BAN",M+410,y+7);
    y+=22;

    topIps.forEach((row,i)=>{
      const bg=i%2===0?"#ffffff":"#fafbfc";
      doc.rect(M,y,W-2*M,22).fillAndStroke(bg,LINE);
      doc.fillColor(TEXT).fontSize(9).font("Helvetica").text(row.ip||"-",M+10,y+7);
      doc.fillColor(TEXT2).text(row.country||"??",M+200,y+7);
      doc.fillColor(TEXT).font("Helvetica-Bold").text(String(row.total_events),M+260,y+7);
      const sc=row.max_score||0;
      const scColor=sc>=70?RED:sc>=40?ORANGE:GREEN;
      doc.rect(M+318,y+4,32,14).fill(scColor);
      doc.fillColor("#ffffff").fontSize(9).font("Helvetica-Bold").text(String(sc),M+318,y+7,{width:32,align:"center"});
      doc.fillColor(TEXT).text(String(row.times_banned||0),M+410,y+7);
      y+=22;
    });
    y+=14;

    doc.fillColor(NAVY).fontSize(11).font("Helvetica-Bold").text("AKTIF BANLI IP LISTESI",M,y);
    doc.strokeColor(GOLD).lineWidth(2).moveTo(M,y+16).lineTo(M+80,y+16).stroke();
    y+=26;

    const ab=banned.filter(b=>b.active===1);
    if(!ab.length){
      doc.rect(M,y,W-2*M,50).fillAndStroke("#f7f9fb",LINE);
      doc.fillColor(TEXT3).fontSize(10).font("Helvetica").text("Aktif ban yok.",M,y+20,{width:W-2*M,align:"center"});
    } else {
      doc.rect(M,y,W-2*M,22).fill(NAVY);
      doc.fillColor("#ffffff").fontSize(9).font("Helvetica-Bold");
      doc.text("IP",M+10,y+7);
      doc.text("SALDIRI",M+180,y+7);
      doc.text("SKOR",M+290,y+7);
      doc.text("ULKE",M+345,y+7);
      doc.text("BAN ZAMANI",M+400,y+7);
      y+=22;
      ab.slice(0,14).forEach((b,i)=>{
        const bg=i%2===0?"#ffffff":"#fafbfc";
        doc.rect(M,y,W-2*M,22).fillAndStroke(bg,LINE);
        doc.fillColor(TEXT).fontSize(9).font("Helvetica").text((b.ip||"-").substring(0,30),M+10,y+7);
        const at=b.attack_type||"-";
        const atColor=typeColors[at]||TEXT3;
        doc.fillColor(atColor).font("Helvetica-Bold").text(at.toUpperCase().substring(0,14),M+180,y+7);
        const sc=b.score||0;
        const scColor=sc>=70?RED:sc>=40?ORANGE:GREEN;
        doc.rect(M+288,y+4,32,14).fill(scColor);
        doc.fillColor("#ffffff").fontSize(9).font("Helvetica-Bold").text(String(sc),M+288,y+7,{width:32,align:"center"});
        doc.fillColor(TEXT2).font("Helvetica").text(b.country||"??",M+345,y+7);
        doc.fillColor(TEXT2).fontSize(8).text(new Date(b.banned_at*1000).toLocaleString("tr-TR"),M+400,y+7);
        y+=22;
      });
    }

    doc.rect(0,H-36,W,36).fill(NAVY);
    doc.fillColor("#aaaaaa").fontSize(8).font("Helvetica").text("Adaptive Firewall System v3.0  -  Bitirme Projesi  -  Otomatik Olusturuldu",M,H-24,{width:W-2*M,align:"center"});
    doc.fillColor(GOLD).fontSize(8).text(new Date().toLocaleString("tr-TR"),M,H-12,{width:W-2*M,align:"center"});

    doc.end();
  } catch (err) {
    console.error("PDF hatasi:",err);
    res.status(500).json({ok:false,error:err.message});
  }
});

pool = mysql.createPool({ ...DB_CONFIG, waitForConnections: true, connectionLimit: 5 });

pool.query("SELECT 1").then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log("");
    console.log("  Adaptive Firewall — Dashboard (MySQL)");
    console.log(`  URL: http://localhost:${PORT}`);
    console.log("");
  });
}).catch(err => {
  console.error("MySQL baglanti hatasi:", err.message);
  process.exit(1);
});
