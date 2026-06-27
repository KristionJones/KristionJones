// Front-end logic for the honeypot dashboard.
// Polls the JSON API and renders KPI cards, charts and the live event feed.

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(url + " -> " + r.status);
  return r.json();
}

// ---------------------------------------------------------------------------
// Tiny self-contained canvas charts (no Chart.js / no CDN — works fully offline)
// ---------------------------------------------------------------------------
function fitCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth || cv.parentElement.clientWidth;
  const h = parseInt(cv.getAttribute("height")) || 110;
  cv.width = w * dpr;
  cv.height = h * dpr;
  cv.style.width = w + "px";
  cv.style.height = h + "px";
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

function drawLineChart(cv, labels, data) {
  const { ctx, w, h } = fitCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  const padL = 34, padB = 22, padT = 10, padR = 8;
  const plotW = w - padL - padR, plotH = h - padB - padT;
  const max = Math.max(1, ...data);
  ctx.strokeStyle = "#1f2a3a";
  ctx.fillStyle = "#7d8da3";
  ctx.font = "10px monospace";
  for (let i = 0; i <= 4; i++) {
    const y = padT + (plotH * i) / 4;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
    ctx.fillText(Math.round(max * (1 - i / 4)), 4, y + 3);
  }
  if (!data.length) return;
  const xstep = data.length > 1 ? plotW / (data.length - 1) : 0;
  const xy = (i, v) => [padL + i * xstep, padT + plotH * (1 - v / max)];
  // area fill
  const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
  grad.addColorStop(0, "rgba(34,211,238,.35)");
  grad.addColorStop(1, "rgba(34,211,238,0)");
  ctx.beginPath();
  ctx.moveTo(padL, padT + plotH);
  data.forEach((v, i) => ctx.lineTo(...xy(i, v)));
  ctx.lineTo(padL + (data.length - 1) * xstep, padT + plotH);
  ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
  // line
  ctx.beginPath();
  data.forEach((v, i) => (i ? ctx.lineTo(...xy(i, v)) : ctx.moveTo(...xy(i, v))));
  ctx.strokeStyle = "#22d3ee"; ctx.lineWidth = 2; ctx.stroke();
  // x labels (first / mid / last)
  ctx.fillStyle = "#7d8da3";
  [0, Math.floor(data.length / 2), data.length - 1].forEach((i) => {
    if (labels[i]) ctx.fillText(String(labels[i]).slice(5), padL + i * xstep - 14, h - 6);
  });
}

function drawDoughnut(cv, labels, data) {
  const { ctx, w, h } = fitCanvas(cv);
  ctx.clearRect(0, 0, w, h);
  const colors = ["#22d3ee", "#a855f7", "#f59e0b", "#ef4444", "#22c55e", "#3b82f6"];
  const total = data.reduce((a, b) => a + b, 0) || 1;
  const cx = h, cy = h / 2, r = h / 2 - 6, ir = r * 0.58;
  let start = -Math.PI / 2;
  data.forEach((v, i) => {
    const ang = (v / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, start + ang);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.fill();
    start += ang;
  });
  ctx.fillStyle = "#0f1623";
  ctx.beginPath(); ctx.arc(cx, cy, ir, 0, Math.PI * 2); ctx.fill();
  // legend
  ctx.font = "11px monospace";
  labels.forEach((lab, i) => {
    const ly = 14 + i * 18;
    ctx.fillStyle = colors[i % colors.length];
    ctx.fillRect(h * 2 + 6, ly - 8, 10, 10);
    ctx.fillStyle = "#e5edf5";
    ctx.fillText(`${lab} (${data[i]})`, h * 2 + 22, ly + 1);
  });
}

function renderCards(s) {
  const cards = [
    { k: "Total attacks", v: s.total_events, cls: "accent" },
    { k: "Unique attackers", v: s.unique_attackers, cls: "danger" },
    { k: "Credential attempts", v: s.credential_attempts, cls: "" },
    { k: "Services targeted", v: s.services_targeted, cls: "" },
    { k: "Last seen", v: s.last_seen || "—", cls: "" },
  ];
  $("cards").innerHTML = cards
    .map(
      (c) =>
        `<div class="card"><div class="k">${c.k}</div>
         <div class="v ${c.cls}">${esc(c.v)}</div></div>`
    )
    .join("");
}

function renderBars(elId, rows) {
  if (!rows.length) {
    $(elId).innerHTML = '<div class="empty">no data yet</div>';
    return;
  }
  const max = Math.max(...rows.map((r) => r.count));
  $(elId).innerHTML = rows
    .map((r) => {
      const w = Math.max(4, (r.count / max) * 100);
      return `<div class="barrow">
        <span class="lbl" title="${esc(r.key)}">${esc(r.key)}</span>
        <span class="bar" style="width:${w}%"></span>
        <span class="num">${r.count}</span></div>`;
    })
    .join("");
}

function renderFeed(rows) {
  if (!rows.length) {
    $("feed").innerHTML =
      '<tr><td colspan="8" class="empty">No events yet — start the sensor or run the attack simulator.</td></tr>';
    return;
  }
  $("feed").innerHTML = rows
    .map((e) => {
      const cls =
        e.ip_class === "public"
          ? '<span class="tag pub">public</span>'
          : `<span class="tag priv">${esc(e.ip_class)}</span>`;
      return `<tr>
        <td>${esc(e.iso_time)}</td>
        <td>${esc(e.service)}</td>
        <td>${esc(e.src_ip)}</td>
        <td>${esc(e.dst_port)}</td>
        <td>${cls}</td>
        <td>${esc(e.username || "")}</td>
        <td>${esc(e.password || "")}</td>
        <td><code>${esc(e.data_preview || "")}</code></td>
      </tr>`;
    })
    .join("");
}

function renderTimeline(rows) {
  drawLineChart($("timeline"), rows.map((r) => r.bucket), rows.map((r) => r.count));
}

function renderServices(rows) {
  drawDoughnut($("services"), rows.map((r) => r.key), rows.map((r) => r.count));
}

async function refresh() {
  try {
    const [stats, ts, services, ip, user, pass, feed] = await Promise.all([
      getJSON("/api/stats"),
      getJSON("/api/timeseries?bucket=3600"),
      getJSON("/api/top?field=service&limit=6"),
      getJSON("/api/top?field=src_ip&limit=10"),
      getJSON("/api/top?field=username&limit=10"),
      getJSON("/api/top?field=password&limit=10"),
      getJSON("/api/events?limit=120"),
    ]);
    renderCards(stats);
    renderTimeline(ts);
    renderServices(services);
    renderBars("topip", ip);
    renderBars("topuser", user);
    renderBars("toppass", pass);
    renderFeed(feed);
  } catch (e) {
    console.error(e);
  }
}

refresh();
setInterval(refresh, 5000);
window.addEventListener("resize", refresh);
