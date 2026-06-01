/**
 * Adaptive Firewall — Dashboard Frontend Mantigi
 */

// ─── DURUM ────────────────────────────────────────────────────────────────────
let flowChart = null;
let leafletMap = null;
const mapMarkers = {};
let wsConnected = false;
let startTime = Date.now();
let prevEventCount = 0;
let leafletLoaded = false;

// ─── GUVENLIK: HTML KACIS ─────────────────────────────────────────────────────
// Saldiri detaylari XSS payload icerebilir — ekrana basmadan once temizle
function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}


const TYPE_LABEL = {
  brute_force: "BRUTE FORCE",
  port_scan: "PORT SCAN",
  ddos: "DDOS",
  xss: "XSS",
  sqli: "SQL INJ",
  path_traversal: "PATH TRV",
  command_injection: "CMD INJ",
  bot: "BOT",
  honeypot: "HONEYPOT",
  mixed: "KARMA",
  manual: "MANUEL",
};

// Ulke -> [lat, lon]
const COUNTRY_LL = {
  RU:[55,37], CN:[35,105], US:[38,-97], DE:[51,10], NL:[52,5],
  FR:[46,2], BR:[-15,-47], IN:[20,77], KR:[36,128], JP:[36,138],
  UA:[49,32], IR:[32,53], TR:[39,35], GB:[54,-2], PK:[30,70],
  VN:[16,108], ID:[-5,120], NG:[9,8], MX:[24,-102], AU:[-25,133],
  CA:[56,-106], AR:[-34,-64], ZA:[-29,25], EG:[26,30], PL:[52,20],
  RO:[46,25], IT:[42,12], ES:[40,-4], SE:[62,15], FI:[64,26],
};

// ─── NAVIGASYON ───────────────────────────────────────────────────────────────
function go(page, btn) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  document.getElementById("pg-" + page).classList.add("active");
  if (btn) btn.classList.add("active");
  if (page === "overview" && leafletMap) {
    setTimeout(() => leafletMap.invalidateSize(), 100);
  }
}

// ─── LEAFLET HARITA ───────────────────────────────────────────────────────────
function loadLeaflet(cb) {
  if (window.L) { cb(); return; }
  const css = document.createElement("link");
  css.rel = "stylesheet";
  css.href = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css";
  document.head.appendChild(css);
  const js = document.createElement("script");
  js.src = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js";
  js.onload = cb;
  document.head.appendChild(js);
}

function initMap() {
  if (!window.L || leafletMap) return;
  leafletMap = L.map("wmap", {
    zoomControl: true, attributionControl: false,
    scrollWheelZoom: false, minZoom: 1, maxZoom: 6,
  }).setView([28, 14], 1);
  L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}{r}.png"
  ).addTo(leafletMap);
  leafletLoaded = true;
}

// IP'den sabit kucuk ofset uret (her render'da ayni kalsin)
function ipJitter(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) | 0;
  const jx = ((h % 100) / 100 - 0.5) * 6;
  const jy = ((Math.floor(h / 100) % 100) / 100 - 0.5) * 6;
  return [jx, jy];
}

function updateMap(banned) {
  if (!leafletLoaded) return;
  // Mevcut IP listesi
  const currentIps = new Set(banned.map(b => b.ip));
  // Artik banli olmayan markerlari kaldir
  Object.keys(mapMarkers).forEach(ip => {
    if (!currentIps.has(ip)) {
      leafletMap.removeLayer(mapMarkers[ip]);
      delete mapMarkers[ip];
    }
  });
  let count = 0;
  banned.forEach(b => {
    const ll = COUNTRY_LL[b.country];
    if (!ll) return;
    count++;
    // Zaten ekli marker varsa dokunma — oynamasin
    if (mapMarkers[b.ip]) return;
    const [jx, jy] = ipJitter(b.ip);
    const marker = L.circleMarker([ll[0] + jy, ll[1] + jx], {
      radius: 7, fillColor: "#d4332a", color: "#fff",
      weight: 2, fillOpacity: 0.9,
    }).bindPopup(
      `<div style="font-family:monospace;font-size:11px">
        <b>${esc(b.ip)}</b><br>
        ${esc(b.country || "?")} / ${esc(b.city || "?")}<br>
        skor: ${b.score} | ${esc(b.attack_type || "?")}
      </div>`
    ).addTo(leafletMap);
    mapMarkers[b.ip] = marker;
  });
  document.getElementById("map-tag").textContent = count + " NOKTA";
}

// ─── CHART ────────────────────────────────────────────────────────────────────
function initChart() {
  const ctx = document.getElementById("flowChart");
  flowChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0")),
      datasets: [{
        data: Array(24).fill(0),
        borderColor: "#1862d8",
        backgroundColor: "rgba(24,98,216,0.08)",
        borderWidth: 2, tension: 0.35, fill: true,
        pointRadius: 0, pointHoverRadius: 4,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: { legend: { display: false } },
      scales: {
        x: {
          grid: { color: "rgba(43,90,160,0.07)" },
          ticks: { color: "#8a96a3", font: { size: 9, family: "monospace" } },
        },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(43,90,160,0.07)" },
          ticks: { color: "#8a96a3", font: { size: 9, family: "monospace" }, precision: 0 },
        },
      },
    },
  });
}

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────
function connectWS() {
  const ws = new WebSocket(`ws://${location.host}`);
  ws.onopen = () => {
    wsConnected = true;
    document.getElementById("conn-led").classList.add("live");
    document.getElementById("conn-text").textContent = "canli baglanti";
    document.getElementById("info-conn").textContent = "Aktif (WebSocket)";
  };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "update") render(msg.data);
  };
  ws.onclose = () => {
    wsConnected = false;
    document.getElementById("conn-led").classList.remove("live");
    document.getElementById("conn-text").textContent = "baglanti kesildi";
    setTimeout(connectWS, 3000);
  };
}

// ─── RENDER ───────────────────────────────────────────────────────────────────
function render(data) {
  if (!data) return;
  const banned = data.banned || [];
  const events = data.events || [];
  const stats = data.stats || {};
  const profiles = data.profiles || [];

  // METRIKLER
  document.getElementById("m-bans").textContent = banned.length;
  document.getElementById("m-events").textContent = stats.total_events || 0;
  document.getElementById("m-events-24h").textContent =
    "son 24s: " + (stats.events_24h || 0);
  document.getElementById("m-ips").textContent = stats.unique_ips || 0;
  document.getElementById("nav-bans").textContent = banned.length;
  document.getElementById("ov-meta").textContent =
    "guncellendi // " + new Date().toLocaleTimeString("tr-TR");

  // TEHDIT SEVIYESI
  const threat = document.getElementById("threat");
  const lv = document.getElementById("threat-lv");
  const txt = document.getElementById("threat-txt");
  if (banned.length >= 3) {
    threat.className = "threat threat-high";
    lv.textContent = "KRITIK";
    txt.textContent = banned.length + " IP aktif olarak engellenmis durumda.";
  } else if (banned.length >= 1 || (stats.events_24h || 0) > 15) {
    threat.className = "threat threat-med";
    lv.textContent = "ORTA";
    txt.textContent = "Saldiri aktivitesi tespit edildi, sistem mudahale ediyor.";
  } else {
    threat.className = "threat threat-low";
    lv.textContent = "DUSUK";
    txt.textContent = "Sistem normal calisiyor, aktif tehdit yok.";
  }

  // TEHDIT ENDEKSI (gauge)
  const idx = Math.min(banned.length * 22 + Math.min(stats.events_24h || 0, 40), 100);
  const arc = document.getElementById("gauge-arc");
  arc.style.strokeDashoffset = 198 - (idx / 100) * 198;
  arc.style.stroke = idx >= 70 ? "#d4332a" : idx >= 40 ? "#c47d10" : "#1f8a4c";
  document.getElementById("gauge-num").textContent = idx;

  // CHART — saatlik
  if (flowChart && stats.hourly) {
    flowChart.data.datasets[0].data = stats.hourly;
    flowChart.update();
  }

  // TUR DAGILIMI
  renderTypeBars(stats.by_type || {});

  // HARITA
  updateMap(banned);

  // CANLI FEED
  renderFeed(events);

  // TABLOLAR
  renderAttacksTable(events);
  renderBannedTable(banned);
  renderProfilesTable(profiles);

  // AYARLAR
  if (data.settings) fillSettings(data.settings);

  // UPTIME
  const up = Math.floor((Date.now() - startTime) / 1000);
  document.getElementById("info-uptime").textContent = up + " sn";
}

function renderTypeBars(byType) {
  const box = document.getElementById("type-bars");
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    box.innerHTML = '<div class="empty" style="padding:20px"><div class="empty-mark">[ ]</div>veri yok</div>';
    return;
  }
  const max = Math.max(...entries.map(e => e[1]), 1);
  const colors = {
    brute_force: "#d4332a", port_scan: "#1f8a4c", ddos: "#c47d10",
    xss: "#1862d8", sqli: "#7d34a8", path_traversal: "#c05d12",
    command_injection: "#b52d2d", bot: "#44515f", honeypot: "#0e1726",
  };
  box.innerHTML = entries.map(([type, count]) => `
    <div class="barline">
      <div class="barline-top">
        <span>${TYPE_LABEL[type] || type}</span>
        <span style="color:#8a96a3">${count}</span>
      </div>
      <div class="barline-track">
        <div class="barline-fill" style="width:${(count / max) * 100}%;background:${colors[type] || "#1862d8"}"></div>
      </div>
    </div>
  `).join("");
}

function renderFeed(events) {
  const feed = document.getElementById("feed");
  if (!events.length) {
    feed.innerHTML = '<div class="empty"><div class="empty-mark">[ ]</div>olay bekleniyor...</div>';
    return;
  }
  feed.innerHTML = events.slice(0, 25).map(e => {
    const t = new Date(e.created_at * 1000).toLocaleTimeString("tr-TR");
    return `
      <div class="feed-row">
        <span class="feed-type t-${e.attack_type}">${TYPE_LABEL[e.attack_type] || e.attack_type}</span>
        <span class="feed-ip">${esc(e.ip)}</span>
        <span class="feed-detail">${esc(e.detail || "")}</span>
        <span class="feed-time">${t}</span>
      </div>
    `;
  }).join("");
  prevEventCount = events.length;
}

function renderAttacksTable(events) {
  const tbl = document.getElementById("attacks-tbl");
  if (!events.length) {
    tbl.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="empty-mark">[ ]</div>Kayit yok</div></td></tr>';
    return;
  }
  tbl.innerHTML = events.map(e => {
    const t = new Date(e.created_at * 1000).toLocaleString("tr-TR");
    const sc = e.score >= 70 ? "#d4332a" : e.score >= 40 ? "#c47d10" : "#1f8a4c";
    return `
      <tr>
        <td><span class="cell-ip">${esc(e.ip)}</span></td>
        <td><span class="feed-type t-${e.attack_type}">${TYPE_LABEL[e.attack_type] || e.attack_type}</span></td>
        <td style="font-family:monospace;font-size:11px;color:#8a96a3">${esc(e.detail || "-")}</td>
        <td><span class="cell-score" style="color:${sc}">${e.score}</span></td>
        <td>${esc(e.country || "??")}</td>
        <td style="font-family:monospace;font-size:11px;color:#8a96a3">${t}</td>
      </tr>
    `;
  }).join("");
}

function renderBannedTable(banned) {
  const tbl = document.getElementById("banned-tbl");
  document.getElementById("ban-tag").textContent = banned.length + " KAYIT";
  if (!banned.length) {
    tbl.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-mark">[ ]</div>Banli IP yok</div></td></tr>';
    return;
  }
  tbl.innerHTML = banned.map(b => {
    const sc = b.score >= 70 ? "#d4332a" : b.score >= 40 ? "#c47d10" : "#1f8a4c";
    // Kalici ban — ne kadar suredir banli
    let banAge = "az once";
    if (b.banned_at) {
      const secs = Math.floor(Date.now() / 1000 - b.banned_at);
      if (secs < 60) banAge = secs + " sn";
      else if (secs < 3600) banAge = Math.floor(secs / 60) + " dk";
      else if (secs < 86400) banAge = Math.floor(secs / 3600) + " saat";
      else banAge = Math.floor(secs / 86400) + " gun";
    }
    let reason = (b.reason || "").length > 30
      ? b.reason.slice(0, 30) + "..." : (b.reason || "-");
    reason = esc(reason);
    return `
      <tr>
        <td><span class="cell-ip">${esc(b.ip)}</span></td>
        <td><span class="feed-type t-${b.attack_type || "manual"}">${TYPE_LABEL[b.attack_type] || b.attack_type || "?"}</span></td>
        <td><span class="cell-score" style="color:${sc}">${b.score}</span></td>
        <td>${esc(b.country || "??")} ${esc(b.city || "")}</td>
        <td style="font-family:monospace;font-size:10px;color:#8a96a3">${reason}</td>
        <td style="font-family:monospace;font-size:11px" title="kalici ban">${banAge} once</td>
        <td>
          <button class="act act-view" onclick="openDrawer('${esc(b.ip)}')">DETAY</button>
          <button class="act act-unban" onclick="confirmUnban('${esc(b.ip)}')">KALDIR</button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderProfilesTable(profiles) {
  const tbl = document.getElementById("profiles-tbl");
  if (!profiles.length) {
    tbl.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-mark">[ ]</div>Profil yok</div></td></tr>';
    return;
  }
  tbl.innerHTML = profiles.map(p => {
    const last = p.last_seen
      ? new Date(p.last_seen * 1000).toLocaleString("tr-TR") : "-";
    const sc = p.max_score >= 70 ? "#d4332a" : p.max_score >= 40 ? "#c47d10" : "#1f8a4c";
    return `
      <tr>
        <td><span class="cell-ip">${esc(p.ip)}</span></td>
        <td>${esc(p.country || "??")}</td>
        <td><strong>${p.total_events}</strong></td>
        <td><span class="cell-score" style="color:${sc}">${p.max_score}</span></td>
        <td>${p.times_banned || 0}</td>
        <td style="font-family:monospace;font-size:11px;color:#8a96a3">${last}</td>
        <td><button class="act act-view" onclick="openDrawer('${esc(p.ip)}')">DETAY</button></td>
      </tr>
    `;
  }).join("");
}

// ─── AYARLAR ──────────────────────────────────────────────────────────────────
const SETTING_FIELDS = [
  "ban_score", "graylist_score", "ban_duration",
  "brute_force_count", "brute_force_window",
  "slow_brute_count", "slow_brute_window",
  "port_scan_count", "port_scan_window",
  "ddos_count", "ddos_window",
  "foreign_penalty", "night_multiplier",
  "mixed_attack_bonus", "web_attack_window",
];

function fillSettings(s) {
  SETTING_FIELDS.forEach(f => {
    const el = document.getElementById("s-" + f);
    if (el && s[f] !== undefined && document.activeElement !== el) {
      el.value = s[f];
    }
  });
}

function confirmSaveSettings() {
  // Onceki ve yeni degerleri karsilastir, ozet goster
  const changed = [];
  SETTING_FIELDS.forEach(f => {
    const el = document.getElementById("s-" + f);
    if (el) changed.push(`${f} = ${el.value}`);
  });
  showConfirm(
    "Kural Degisikligini Uygula",
    "Yeni kurallar guvenlik duvarina aninda uygulanacak. Devam edilsin mi?",
    changed.slice(0, 6).join("\n"),
    doSaveSettings
  );
}

async function doSaveSettings() {
  const payload = {};
  SETTING_FIELDS.forEach(f => {
    const el = document.getElementById("s-" + f);
    if (el) payload[f] = parseInt(el.value) || 0;
  });
  await fetch("/api/settings", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const box = document.getElementById("set-saved");
  box.classList.add("show");
  setTimeout(() => box.classList.remove("show"), 3500);
}

// ─── ONAY MODALI ──────────────────────────────────────────────────────────────
let confirmCallback = null;

function showConfirm(head, body, detail, cb) {
  document.getElementById("cm-head").textContent = head;
  document.getElementById("cm-body").textContent = body;
  const det = document.getElementById("cm-detail");
  if (detail) {
    det.style.display = "block";
    det.textContent = detail;
  } else {
    det.style.display = "none";
  }
  confirmCallback = cb;
  document.getElementById("confirm-modal").classList.add("open");
}

function closeConfirm() {
  document.getElementById("confirm-modal").classList.remove("open");
  confirmCallback = null;
}

document.getElementById("cm-ok").onclick = () => {
  if (confirmCallback) confirmCallback();
  closeConfirm();
};

function confirmAction(action) {
  if (action === "unban-all") {
    showConfirm(
      "Tum Banlari Kaldir",
      "Tum aktif banlar kaldirilacak. Bu islem geri alinamaz.",
      null,
      async () => {
        await fetch("/api/unban-all", { method: "POST" });
      }
    );
  }
}

function confirmUnban(ip) {
  showConfirm(
    "Bani Kaldir",
    `${ip} adresinin engeli kaldirilacak. Emin misiniz?`,
    `hedef: ${ip}`,
    async () => {
      await fetch("/api/unban", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
    }
  );
}

// ─── MANUEL BAN ───────────────────────────────────────────────────────────────
function openBanModal() {
  document.getElementById("ban-ip-input").value = "";
  document.getElementById("ban-modal").classList.add("open");
}
function closeBanModal() {
  document.getElementById("ban-modal").classList.remove("open");
}
async function doManualBan() {
  const ip = document.getElementById("ban-ip-input").value.trim();
  if (!ip) return;
  await fetch("/api/ban", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip }),
  });
  closeBanModal();
}

// ─── IP DETAY DRAWER ──────────────────────────────────────────────────────────
async function openDrawer(ip) {
  document.getElementById("dr-ip").textContent = ip;
  document.getElementById("dr-body").innerHTML =
    '<div class="empty">yukleniyor...</div>';
  document.getElementById("drawer-bg").classList.add("open");
  document.getElementById("drawer").classList.add("open");

  try {
    const res = await fetch("/api/ip/" + encodeURIComponent(ip));
    const data = await res.json();
    const events = data.events || [];
    const profile = data.profile || {};

    let html = `
      <table class="kv-table" style="width:100%;margin-bottom:16px">
        <tr><td>Ulke</td><td>${esc(profile.country || "??")}</td></tr>
        <tr><td>Toplam olay</td><td>${profile.total_events || events.length}</td></tr>
        <tr><td>Maksimum skor</td><td>${profile.max_score || 0}</td></tr>
        <tr><td>Ban sayisi</td><td>${profile.times_banned || 0}</td></tr>
      </table>
      <div class="panel-title" style="margin-bottom:8px">Olay Gecmisi (${events.length})</div>
    `;

    if (events.length) {
      html += '<div class="feed">';
      events.slice(0, 30).forEach(e => {
        const t = new Date(e.created_at * 1000).toLocaleString("tr-TR");
        html += `
          <div class="feed-row">
            <span class="feed-type t-${e.attack_type}">${TYPE_LABEL[e.attack_type] || e.attack_type}</span>
            <span class="feed-detail">${esc(e.detail || "")}</span>
            <span class="feed-time">${t}</span>
          </div>
        `;
      });
      html += "</div>";
    } else {
      html += '<div class="empty">olay kaydi yok</div>';
    }

    document.getElementById("dr-body").innerHTML = html;
    document.getElementById("dr-sub").textContent =
      events.length + " olay kaydi";
  } catch {
    document.getElementById("dr-body").innerHTML =
      '<div class="empty">veri alinamadi</div>';
  }
}

function closeDrawer() {
  document.getElementById("drawer-bg").classList.remove("open");
  document.getElementById("drawer").classList.remove("open");
}

// ─── TELEGRAM ─────────────────────────────────────────────────────────────────
async function testTelegram() {
  const token = document.getElementById("tg-token").value.trim();
  const chatId = document.getElementById("tg-chat").value.trim();
  const message = document.getElementById("tg-msg").value.trim();
  const box = document.getElementById("tg-msg-box");

  if (!token || !chatId) {
    box.className = "inline-msg err show";
    box.textContent = "Token ve Chat ID gerekli.";
    return;
  }

  try {
    const res = await fetch("/api/telegram", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, chatId, message }),
    });
    const data = await res.json();
    box.className = "inline-msg " + (data.ok ? "ok" : "err") + " show";
    box.textContent = data.ok
      ? "Mesaj gonderildi. Token kaydedildi, banlarda otomatik bildirim gelecek."
      : "Gonderilemedi. Token/Chat ID kontrol edin.";
  } catch {
    box.className = "inline-msg err show";
    box.textContent = "Baglanti hatasi.";
  }
}

// ─── YUKLEME ──────────────────────────────────────────────────────────────────
async function loadAll() {
  try {
    const res = await fetch("/api/dashboard");
    const data = await res.json();
    render(data);
  } catch (e) {
    console.error(e);
  }
}

// ─── BASLAT ───────────────────────────────────────────────────────────────────
initChart();
loadLeaflet(() => {
  initMap();
  loadAll();
});
connectWS();
loadAll();
setInterval(loadAll, 15000);
