"use strict";
/* AgentSnap console. No build step, no external libraries. */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const n = v => (v ?? 0).toLocaleString("en-IN");
const inr = v => "₹" + Math.round(v).toLocaleString("en-IN");
const money = v => v == null ? "" : v >= 1e7 ? `₹${(v / 1e7).toFixed(1).replace(/\.0$/, "")} cr` : v >= 1e5 ? `₹${(v / 1e5).toFixed(v >= 1e6 ? 1 : 2).replace(/\.0+$/, "")} L` : inr(v);
const LABEL = { allow: "Allowed", step_up: "Step-up", hold: "Held", block: "Blocked" };
const badge = a => `<span class="badge ${a}">${LABEL[a] || esc(a)}</span>`;
const VERB = { allow: "Allow", step_up: "Step-up", hold: "Hold", block: "Block" };
const verb = a => `<span class="badge ${a}">${VERB[a] || esc(a)}</span>`;
const KIND = { digital_arrest: "Digital arrest", sim_swap: "SIM swap", remote_access: "Remote access", pledge_misuse: "Pledge misuse",
  mule_rent: "Mule rental", fake_kyc: "Fake KYC", dormant_takeover: "Dormant takeover", callback: "callback", classic: "classic",
  liquidation: "liquidation", credential_theft: "credential theft", mobile_swap: "mobile swap", burst: "burst", slow: "slow",
  excess: "excess", third_party: "third party", fake_support: "fake support", fast: "fast" };
const kind = k => KIND[k] || String(k).replace(/_/g, " ");
const PROVIDER = { caller_registry: "Caller registry", sim_swap: "SIM swap", number_verification: "Number verification" };
const icon = id => `<svg class="i"><use href="#i-${id}"/></svg>`;
const ini = s => s.split(/[ ,]/).filter(Boolean)[0][0];
async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(j.error || r.statusText), { data: j });
  return j;
}
const post = (p, body) => api(p, { method: "POST", body: body ? JSON.stringify(body) : undefined });
function dur(s) {
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${+(s / 3600).toFixed(1)}h`;
  return `${+(s / 86400).toFixed(1)}d`;
}
const offset = s => s === 0 ? "0:00" : s < 0 ? "−" + dur(-s) : "+" + dur(s);
const clock = ts => new Date(ts * 1000).toLocaleString("en-IN", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "Asia/Kolkata" });
function toast(msg) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = msg;
  document.body.appendChild(t); setTimeout(() => t.remove(), 3200);
}

/* theme, navigation, drawer */
try { const t = localStorage.getItem("as.theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
$("#theme").onclick = () => {
  const r = document.documentElement; r.dataset.theme = r.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("as.theme", r.dataset.theme); } catch (e) {}
  VIEWS[current]?.redraw?.();
};
const INIT_HASH = location.hash;
let current = null;
const VIEWS = {};
function show(v) {
  if (current === v) return;
  current = v;
  $$("#nav button").forEach(b => b.classList.toggle("on", b.dataset.view === v));
  $$(".view").forEach(s => s.hidden = s.id !== "v-" + v);
  VIEWS[v]?.enter?.();
  try { localStorage.setItem("as.view", v); } catch (e) {}
  history.replaceState(null, "", "#" + v);
}
$("#nav").onclick = e => { const b = e.target.closest("[data-view]"); if (b) show(b.dataset.view); };
function drawer(title, html) { $("#drawer-title").textContent = title; $("#drawer-body").innerHTML = html; $("#drawer").hidden = $("#scrim").hidden = false; $("#drawer").scrollTop = 0; }
const closeDrawer = () => { $("#drawer").hidden = $("#scrim").hidden = true; };
$("#drawer-close").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

let POLICY = null;
const policy = async () => POLICY || (POLICY = await api("/api/policy"));
const hl = src => esc(src)
  .replace(/(#[^\n]*)/g, '<span class="cm">$1</span>')
  .replace(/\b(rule|on|where|then|explain|lesson|tags|and|or|not|in|hold|block|step_up|allow|guardian)\b/g, '<span class="kw">$1</span>')
  .replace(/\b(once|never|count|distinct|sum|since)\b/g, '<span class="tm">$1</span>');

async function decisionDetail(d, ctx = {}) {
  const p = await policy();
  const byId = Object.fromEntries(p.rules.map(r => [r.id, r]));
  const sig = Object.entries(ctx.signals || {}).filter(([k, v]) => v !== null && v !== false && v !== 0 && v !== "none" && !["asn", "ip_24", "degraded"].includes(k) && !(Array.isArray(v) && !v.length));
  drawer(d.etype.replace(/_/g, " "), `
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">${badge(d.action)}${d.hold_secs ? `<span class="badge neutral">${dur(d.hold_secs)}${d.guardian ? " · guardian" : ""}</span>` : ""}<span class="badge neutral">${d.latency_us} µs</span></div>
    ${ctx.text ? `<p>${esc(ctx.text)}</p>` : ""}
    ${(d.flags || []).length ? `<div class="callout neutral">${d.flags.map(esc).join("<br>")}</div>` : ""}
    ${(d.hits || []).map(h => `<div class="rule"><div class="rule-h"><span class="tag">${esc(h.id)}</span><b>${esc(h.name)}</b>${verb(h.action.split(" ")[0])}</div>
      <div class="rule-b"><p>${esc(h.explain)}</p>
      ${Object.keys(h.evidence || {}).length ? `<div style="display:flex;gap:6px;flex-wrap:wrap">${Object.entries(h.evidence).map(([k, v]) => `<span class="tag">${esc(k)} = ${esc(Array.isArray(v) ? v.join(",") : v)}</span>`).join("")}</div>` : ""}
      ${byId[h.id] ? `<pre class="src">${hl(byId[h.id].source)}</pre>` : ""}
      ${h.lesson ? `<p class="note">${esc(h.lesson)}</p>` : ""}</div></div>`).join("") || `<p class="sub">No rule fired.</p>`}
    ${sig.length ? `<div><div class="section-l">Signals</div><dl class="kv">${sig.map(([k, v]) => `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>` : ""}
    <div><div class="section-l">Record</div><dl class="kv"><dt>BO</dt><dd>${esc(d.bo)}</dd><dt>Today's check</dt><dd>${esc(d.local_check)}</dd>${d.policy ? `<dt>Policy</dt><dd>${esc(d.policy)}</dd>` : ""}${d.seq ? `<dt>Audit</dt><dd>#${d.seq} · ${esc((d.hash || "").slice(0, 16))}</dd>` : ""}</dl></div>`);
}

/* ------------------------------------------------------------------ Live */
VIEWS.live = {
  state: null, alerts: [], recent: [], inited: false, busy: false,
  enter() { if (!this.inited) { this.inited = true; this.shell(); this.connect(); } this.poll(); },
  shell() {
    $("#v-live").innerHTML = `
      <div class="top"><h1>Live</h1><span class="sub" id="lv-clock"></span>
        <select id="speed" aria-label="Speed"><option value="40">40 / s</option><option value="200">200 / s</option><option value="1000" selected>1,000 / s</option></select>
        <button class="btn primary" id="lv-start">${icon("play")}Start</button><button class="btn" id="lv-stop">Pause</button><button class="btn" id="lv-reset">Reset</button></div>
      <div class="metrics" id="kpis"></div>
      <div class="grid split">
        <div class="card"><div class="card-h"><h2>Interventions</h2></div><div class="card-b flush scroll tall" id="alerts"></div></div>
        <div class="card"><div class="card-h"><h2>Events</h2></div><div class="card-b flush scroll tall" id="recent"></div></div>
      </div>`;
    $("#lv-start").onclick = async () => { await post("/api/live/start?speed=" + $("#speed").value); this.poll(); };
    $("#lv-stop").onclick = async () => { await post("/api/live/stop"); this.poll(); };
    $("#lv-reset").onclick = async () => { $("#lv-reset").disabled = true; await post("/api/live/reset"); $("#lv-reset").disabled = false; this.poll(); };
    $("#speed").onchange = async () => { if (this.state?.running) await post("/api/live/start?speed=" + $("#speed").value); };
    $("#alerts").onclick = e => { const tr = e.target.closest("[data-i]"); const a = tr && this.alerts[+tr.dataset.i]; if (a) decisionDetail({ ...a, local_check: "OTP / TPIN valid" }, { signals: {} }); };
  },
  connect() {
    try {
      const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
      ws.onmessage = () => { if (current === "live") this.poll(); };
      ws.onclose = () => setTimeout(() => this.connect(), 2000);
    } catch (e) {}
  },
  async poll() {
    if (this.busy) return; this.busy = true;
    try { const s = await api("/api/live/state"); Object.assign(this, { state: s.state, alerts: s.alerts, recent: s.recent }); this.render(); }
    catch (e) { /* server away: keep the last view */ }
    finally { setTimeout(() => this.busy = false, 400); }
  },
  render() {
    const s = this.state, c = s.counts;
    $("#kpis").innerHTML = `
      <div class="metric"><span>Events</span><b>${n(s.processed)}</b><small>of ${n(s.total)}</small></div>
      <div class="metric allow"><span>Allowed</span><b>${n(c.allow)}</b></div>
      <div class="metric step_up"><span>Step-up</span><b>${n(c.step_up)}</b></div>
      <div class="metric hold"><span>Held</span><b>${n(c.hold)}</b><small>${s.holds_pending} pending</small></div>
      <div class="metric block"><span>Blocked</span><b>${n(c.block)}</b></div>`;
    $("#lv-clock").textContent = s.processed ? clock(s.clock) : "";
    $("#lv-start").innerHTML = s.running ? "Running" : `${icon("play")}Start`;
    $("#alerts").innerHTML = this.alerts.length ? `<table><tr><th>Event</th><th class="num">Amount</th><th>Rules</th><th>Decision</th><th>Ground truth</th></tr>${this.alerts.map((r, i) => `
      <tr class="click" data-i="${i}"><td>${esc(r.etype.replace(/_/g, " "))}<div class="id">${esc(r.bo)}</div></td><td class="num">${money(r.value)}</td>
      <td>${r.rules.map(x => `<span class="tag">${x}</span>`).join(" ")}</td><td>${badge(r.action)}</td>
      <td>${r.attack ? `<span class="badge accent">${esc(kind(r.kind))}</span>` : `<span class="badge neutral">Benign</span>`}</td></tr>`).join("")}</table>`
      : `<div class="empty">No interventions yet</div>`;
    $("#recent").innerHTML = this.recent.length ? `<table><tr><th>Event</th><th class="num">Amount</th><th>Decision</th><th class="num">µs</th></tr>${this.recent.slice(0, 40).map(x => `
      <tr><td>${esc(x.etype.replace(/_/g, " "))}<div class="id">${esc(x.bo.slice(-8))}</div></td><td class="num">${money(x.value)}</td><td>${badge(x.action)}</td><td class="num">${x.latency_us}</td></tr>`).join("")}</table>`
      : `<div class="empty">Start the stream</div>`;
  },
};

/* ------------------------------------------------------------------ Kill chains */
VIEWS.chains = {
  list: null, data: null, results: {}, shown: 0, timer: null,
  async enter() {
    if (this.list) return;
    this.list = await api("/api/scenarios");
    $("#v-chains").innerHTML = `
      <div class="top"><h1>Kill chains</h1><button class="btn primary" id="ch-play">${icon("play")}Replay</button></div>
      <div class="chains"><div class="card sc-list" id="sc-list"></div><div class="grid" id="chain"></div></div>`;
    $("#ch-play").onclick = () => this.play();
    this.listHTML();
    await this.load(INIT_HASH.includes("chains-") ? INIT_HASH.split("chains-")[1] : "digital_arrest");
    for (const s of this.list) if (!this.results[s.id]) { this.results[s.id] = await post("/api/replay/" + s.id, {}); this.listHTML(); }
  },
  outcome(r) {
    if (!r) return "";
    if (r.stopped_at) { const a = r.steps[r.stopped_at - 1].decision.action; return `<span class="badge ${a}">${LABEL[a]} ${r.stopped_at}/${r.steps.length}</span>`; }
    return r.id === "family_gift" ? `<span class="badge allow">No friction</span>` : `<span class="badge neutral">Missed</span>`;
  },
  listHTML() {
    $("#sc-list").innerHTML = this.list.map(s => `<button class="sc ${this.data?.id === s.id ? "on" : ""}" data-s="${s.id}"><b>${esc(s.title)}</b><span>${esc(s.who)}</span>${this.outcome(this.results[s.id])}</button>`).join("");
    $("#sc-list").onclick = e => { const b = e.target.closest("[data-s]"); if (b) this.load(b.dataset.s); };
  },
  async load(id) {
    this.stop();
    this.data = this.results[id] || (this.results[id] = await post("/api/replay/" + id, {}));
    this.shown = this.data.steps.length; this.listHTML(); this.render();
  },
  play() {
    this.stop(); this.shown = 0; this.render();
    const tick = () => { this.shown++; this.render(); if (this.shown < this.data.steps.length) this.timer = setTimeout(tick, 1100); };
    this.timer = setTimeout(tick, 300);
  },
  stop() { clearTimeout(this.timer); },
  render() {
    const d = this.data, idx = d.stopped_at ? d.stopped_at - 1 : -1, done = this.shown >= d.steps.length;
    let call = "";
    if (idx >= 0 && this.shown > idx) {
      const a = d.steps[idx].decision.action;
      call = `<div class="callout ${a}"><b>${LABEL[a]} at step ${d.stopped_at} of ${d.steps.length}.</b> Every earlier step passed today's checks.</div>`;
    } else if (done) call = d.id === "family_gift"
      ? `<div class="callout allow"><b>No friction.</b> Saved contact, beneficiary added days earlier.</div>`
      : `<div class="callout neutral"><b>Missed.</b> No call, beneficiary added the day before, amount under the limit. Covered by the opt-in new-beneficiary lock.</div>`;
    $("#chain").innerHTML = `
      <div class="card card-b persona"><div class="avatar">${esc(ini(d.who))}</div><div><h2>${esc(d.title)}</h2><div class="sub">${esc(d.who)}</div><p style="margin-top:6px;font-size:13.5px;color:var(--ink-2)">${esc(d.summary)}</p></div></div>
      ${call}
      <div class="card"><div class="timeline">${d.steps.map((s, i) => { const vis = i < this.shown, a = s.decision.action; return `
        <div class="ev ${vis ? a : "dim"}" data-i="${i}">
          <span class="node"></span><span class="t">${offset(s.t_offset)}</span>
          <div class="what"><small>${esc(s.type.replace(/_/g, " "))}${s.attrs.value ? " · " + money(s.attrs.value) : ""}</small>${esc(s.text)}</div>
          <div class="col"><small>Today</small><span class="badge allow">${esc(s.local_check)}</span></div>
          <div class="col"><small>AgentSnap</small>${vis ? badge(a) : ""}<div class="rules">${vis ? s.decision.hits.map(h => `<span class="tag ${["hold", "block"].includes(h.action.split(" ")[0]) ? "hot" : ""}">${h.id}</span>`).join("") : ""}</div></div>
        </div>`; }).join("")}</div></div>`;
    $("#chain").onclick = e => { const el = e.target.closest(".ev[data-i]"); if (!el || +el.dataset.i >= this.shown) return; const s = d.steps[+el.dataset.i]; decisionDetail(s.decision, { text: s.text, signals: s.signals }); };
  },
};

/* ------------------------------------------------------------------ Investor app */
VIEWS.app = {
  st: null, lang: "en", demoed: false,
  async enter() {
    if (INIT_HASH === "#app-demo" && !this.demoed) { this.demoed = true; await post("/api/app/reset"); for (let i = 0; i < 3; i++) await post("/api/app/next"); }
    this.st = await api("/api/app/state"); this.render();
  },
  async act(p) { this.st = await post(p); this.render(); },
  render() {
    const s = this.st, hold = s.hold, status = hold?.status, hi = this.lang === "hi";
    const trans = s.decisions.find(x => x.type === "offmarket_out");
    const hits = trans ? trans.decision.hits : [];
    const tr = (h, k) => (hi && h.i18n?.hi?.[k]) || h[k];
    const T = hi ? { hold: "होल्डिंग", call: "अनजान नंबर से कॉल चल रही है", tip: "CBI, पुलिस या SEBI कभी शेयर ट्रांसफ़र करने को नहीं कहते। फ़ोन काट दें।",
      ben: "लाभार्थी जोड़ा गया", paused: "ट्रांसफ़र 24 घंटे के लिए रोका गया", left: "₹18.4 लाख के शेयर। आपके खाते से कुछ नहीं गया।", cancel: "ट्रांसफ़र रद्द करें", sure: "फिर भी भेजना है",
      neha: "नेहा (बेटी) को आपको फ़ोन करने को कहा गया है।", safe: "ट्रांसफ़र रद्द। आपके शेयर सुरक्षित हैं।", report: "शिकायत करें: 1930", lock: "सुरक्षा लॉक",
      l1: "DP शाखा के बाहर ऑफ़-मार्केट ट्रांसफ़र रोकें", l2: "इस हफ़्ते जोड़े गए खातों में ट्रांसफ़र पर विराम", g: "अभिभावक: नेहा", bar: "कॉल पर · सेव नहीं" }
      : { hold: "Holdings", call: "Call with an unsaved number", tip: "CBI, police and SEBI never ask you to move shares. Hang up.",
      ben: "Beneficiary added", paused: "Transfer paused for 24 hours", left: "₹18.4 lakh of shares. Nothing has left your account.", cancel: "Cancel transfer", sure: "Send anyway",
      neha: "Neha (daughter) has been asked to call you.", safe: "Transfer cancelled. Your shares are safe.", report: "Report the caller: 1930", lock: "Safety lock",
      l1: "Block off-market transfers outside a DP branch", l2: "Pause transfers to accounts added this week", g: "Guardian: Neha", bar: "On call · not saved" };
    let body = "";
    if (status === "pending") {   // a pause takes over the screen: one reason, one lesson, two choices
      const lh = hits.find(h => h.lesson), why = hits.find(h => h.action.startsWith("hold"));
      body = `<div class="pcard alert"><h3>${T.paused}</h3><p>${T.left}</p><div class="timer">23:59:41</div>
        ${why ? `<div class="reasons"><span>${esc(tr(why, "explain"))}</span></div>` : ""}
        ${lh ? `<div class="lesson-p">${esc(tr(lh, "lesson"))}</div>` : ""}
        <button class="pbtn red" id="a-cancel">${T.cancel}</button><button class="pbtn line" id="a-sure">${T.sure}</button>
        <p style="font-size:11.5px;color:#7A8090;margin-top:8px;text-align:center">${T.neha}</p></div>`;
    } else {
      body = `<div class="pcard"><small>${T.hold}</small><div class="amt">₹24,61,300</div><small>14 securities</small></div>`;
      if (status === "cancelled" || status === "guardian_declined") body += `<div class="pcard ok"><h3>${T.safe}</h3><button class="pbtn dark">${T.report}</button></div>`;
      else if (s.step >= 1) body += `<div class="pcard warn"><h3>${T.call}</h3><p>${T.tip}</p></div>`;
      if (s.step >= 2 && !status) body += `<div class="pcard"><small>${T.ben}</small><div class="mono" style="margin-top:2px">1208MULE0001</div></div>`;
    }
    if (status !== "pending") body += `<div class="pcard"><small>${T.lock}</small>
      <div class="row-t"><span>${T.l1}</span><button class="sw ${s.lock_offmarket ? "on" : ""}" id="a-lock" aria-label="${T.l1}"></button></div>
      <div class="row-t"><span>${T.l2}</span><span class="sw" aria-hidden="true"></span></div>
      <div class="row-t"><span>${T.g}</span><span style="color:#136B3F;font-weight:600">●</span></div></div>`;
    let gb = `<div class="pcard"><small>Asha · mother</small><p>Nothing to review.</p></div>`;
    if (status === "pending") gb = `<div class="pcard alert"><h3>Asha's transfer is paused</h3><p>₹18.4 lakh to an account opened 9 days ago that took shares from 3 strangers today. She is on a call with an unverified number.</p>
      <button class="pbtn dark">Call Asha</button><button class="pbtn red" id="g-decline">Decline</button><button class="pbtn line" id="g-approve">Approve</button></div>`;
    else if (status === "guardian_declined" || status === "cancelled") gb = `<div class="pcard ok"><h3>Nothing left Asha's account</h3><p>The receiving account is now flagged.</p></div>`;
    const phone = (label, app, sub, content, bar) => `<div><div class="device-l">${label}</div><div class="phone"><div class="screen"><div class="island"></div>
      <div class="sbar"><span>10:52</span><span>●●●</span></div>${bar || ""}<div class="apph"><div class="logo">${app[0]}</div><div><b>${app}</b><small>${sub}</small></div></div><div class="appb">${content}</div></div></div></div>`;
    const STEPS = ["A caller posing as CBI says her Aadhaar is linked to money laundering.", "He sends a BO ID on WhatsApp; she adds it as a beneficiary.", "He tells her to move her shares there. AgentSnap pauses it."];
    const LOCAL = ["Login OTP", "OTP valid", "TPIN + OTP valid"];
    $("#v-app").innerHTML = `
      <div class="top"><h1>Investor app</h1><div class="seg"><button class="${hi ? "" : "on"}" id="a-en">English</button><button class="${hi ? "on" : ""}" id="a-hi">हिंदी</button></div>
        <button class="btn primary" id="a-next" ${s.step >= s.total ? "disabled" : ""}>${s.step === 0 ? "Start" : "Next step"}</button><button class="btn" id="a-reset">Reset</button></div>
      <div class="stage">
        ${phone("Asha, 72", "myEasi", "BO 1208ASHA0072", body, s.step >= 1 && status !== "cancelled" && status !== "guardian_declined" ? `<div class="callpill"><span>${T.bar}</span><span>${["04", "39", "56"][Math.min(s.step, 3) - 1]}:12</span></div>` : "")}
        ${phone("Neha, guardian", "AgentSnap", "Guardian", gb)}
        <div class="card card-b"><div class="steps">${STEPS.map((t, i) => `<div class="stp ${i < s.step ? "done" : ""} ${i === s.step - 1 ? "cur" : ""} ${i >= s.step ? "todo" : ""}"><span class="n">${i + 1}</span><div><p>${esc(t)}</p>
          ${s.decisions[i] ? `<div class="row"><span class="badge allow">${LOCAL[i]}</span>${badge(s.decisions[i].decision.action)}${s.decisions[i].decision.hits.map(h => `<span class="tag">${h.id}</span>`).join("")}</div>` : ""}</div></div>`).join("")}</div>
          ${trans ? `<button class="btn" id="a-why" style="margin-top:12px">Why it was paused</button>` : ""}</div>
      </div>`;
    $("#a-en").onclick = () => { this.lang = "en"; this.render(); };
    $("#a-hi").onclick = () => { this.lang = "hi"; this.render(); };
    $("#a-next").onclick = () => this.act("/api/app/next");
    $("#a-reset").onclick = () => this.act("/api/app/reset");
    $("#a-lock").onclick = () => this.act("/api/app/lock/" + (s.lock_offmarket ? 0 : 1));
    if ($("#a-cancel")) $("#a-cancel").onclick = () => this.act("/api/app/hold/cancel");
    if ($("#a-sure")) $("#a-sure").onclick = () => toast("It stays paused until the 24 hours pass or Neha approves.");
    if ($("#g-decline")) $("#g-decline").onclick = () => this.act("/api/app/hold/guardian_decline");
    if ($("#g-approve")) $("#g-approve").onclick = () => this.act("/api/app/hold/guardian_approve");
    if ($("#a-why")) $("#a-why").onclick = () => decisionDetail(trans.decision, { text: STEPS[2] });
  },
};

/* ------------------------------------------------------------------ Mule graph */
VIEWS.graph = {
  data: null, sel: 0,
  async enter() {
    $("#v-graph").innerHTML = `<div class="top"><h1>Mule graph</h1><div class="seg" id="g-pick"></div><button class="btn" id="g-ref">Refresh</button></div>
      <div class="grid split"><div class="card"><canvas id="gcanvas"></canvas></div><div class="card" id="g-info"></div></div>
      <div class="legend"><span><i style="background:var(--allow)"></i>Low</span><span><i style="background:var(--hold)"></i>Medium</span><span><i style="background:var(--block)"></i>High mule score</span><span><i style="width:16px;height:2px;border-radius:0;background:var(--faint);vertical-align:3px"></i>Transfer</span><span><i style="width:16px;height:0;border-radius:0;border-top:2px dashed var(--accent);vertical-align:3px"></i>Same phone</span></div>`;
    $("#g-ref").onclick = () => this.load();
    await this.load();
  },
  async load() {
    let rings = await api("/api/graph/rings");
    if (!rings.length || rings[0].mule_score < 0.3) { const r = await post("/api/replay/digital_arrest", {}); rings = [{ bo: "1208MULE0001", graph: r.graph }]; }
    this.data = rings; this.sel = 0;
    $("#g-pick").innerHTML = rings.map((r, i) => `<button class="${i ? "" : "on"}" data-i="${i}">${esc(r.bo.slice(-6))}</button>`).join("");
    $("#g-pick").onclick = e => { const b = e.target.closest("[data-i]"); if (!b) return; this.sel = +b.dataset.i; $$("#g-pick button").forEach(x => x.classList.toggle("on", x === b)); this.layout(); };
    this.layout();
  },
  layout() {
    const g = this.data[this.sel].graph;
    const nodes = g.nodes.map((v, i) => ({ ...v, x: Math.cos(i * 2.4) * 150, y: Math.sin(i * 2.4) * 150, vx: 0, vy: 0 }));
    const idx = Object.fromEntries(nodes.map((v, i) => [v.bo, i]));
    const edges = g.edges.filter(e => e.src in idx && e.dst in idx);
    for (let it = 0; it < 400; it++) {
      for (const a of nodes) for (const b of nodes) { if (a === b) continue; const dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + .01, f = 2400 / d2, d = Math.sqrt(d2); a.vx += dx / d * f; a.vy += dy / d * f; }
      for (const e of edges) { const a = nodes[idx[e.src]], b = nodes[idx[e.dst]], dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) + .01, f = (d - 120) * .02; a.vx += dx / d * f; a.vy += dy / d * f; b.vx -= dx / d * f; b.vy -= dy / d * f; }
      for (const v of nodes) { v.vx -= v.x * .004; v.vy -= v.y * .004; v.x += v.vx * .5; v.y += v.vy * .5; v.vx *= .6; v.vy *= .6; }
    }
    this.L = { nodes, edges, idx };
    this.redraw();
    const top = [...nodes].sort((a, b) => b.mule_score - a.mule_score)[0];
    const F = [["Mule score", top.mule_score.toFixed(2)], ["Senders, 24h", top.fan_in_24h], ["Passed on", Math.round(top.passthrough * 100) + "%"], ["Account age", top.age_days < 9000 ? top.age_days + " days" : "unknown"], ["Accounts on same phone", top.device_cluster], ["Flagged", top.flagged ? "yes" : "no"]];
    $("#g-info").innerHTML = `<div class="card-h"><h2 class="mono" style="font-size:14px">${esc(top.bo)}</h2>${top.mule_score >= .7 ? `<span class="badge block">High</span>` : top.mule_score >= .3 ? `<span class="badge hold">Medium</span>` : `<span class="badge allow">Low</span>`}</div>
      <div class="card-b"><dl class="kv" style="grid-template-columns:170px 1fr">${F.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>`;
  },
  redraw() {
    const cv = $("#gcanvas"); if (!cv || !this.L || current !== "graph") return;
    const r = cv.getBoundingClientRect(), dpr = devicePixelRatio || 1;
    cv.width = r.width * dpr; cv.height = r.height * dpr;
    const ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    const css = getComputedStyle(document.documentElement), col = k => css.getPropertyValue(k).trim();
    const { nodes, edges, idx } = this.L;
    const xs = nodes.map(v => v.x), ys = nodes.map(v => v.y);
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const s = Math.min((r.width - 160) / (x1 - x0 || 1), (r.height - 80) / (y1 - y0 || 1), 2);
    const P = v => [r.width / 2 + (v.x - (x0 + x1) / 2) * s, r.height / 2 + (v.y - (y0 + y1) / 2) * s];
    for (const e of edges) {
      const [ax, ay] = P(nodes[idx[e.src]]), [bx, by] = P(nodes[idx[e.dst]]), dev = e.kind === "device";
      ctx.strokeStyle = dev ? col("--accent") : col("--faint"); ctx.lineWidth = 1.2; ctx.setLineDash(dev ? [4, 4] : []);
      ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke();
      if (!dev) { const a = Math.atan2(by - ay, bx - ax), ex = bx - Math.cos(a) * 13, ey = by - Math.sin(a) * 13; ctx.setLineDash([]); ctx.fillStyle = col("--faint"); ctx.beginPath(); ctx.moveTo(ex, ey); ctx.lineTo(ex - Math.cos(a - .45) * 7, ey - Math.sin(a - .45) * 7); ctx.lineTo(ex - Math.cos(a + .45) * 7, ey - Math.sin(a + .45) * 7); ctx.fill(); }
    }
    ctx.setLineDash([]);
    for (const v of nodes) {
      const [x, y] = P(v), rad = 6 + Math.min(v.fan_in_24h, 6) * 1.6;
      ctx.fillStyle = v.mule_score >= .7 ? col("--block") : v.mule_score >= .3 ? col("--hold") : col("--allow");
      ctx.beginPath(); ctx.arc(x, y, rad, 0, Math.PI * 2); ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = col("--surface"); ctx.stroke();
      ctx.fillStyle = col("--ink-2"); ctx.font = "11.5px Consolas, monospace"; ctx.fillText(v.bo.slice(-8), x + rad + 5, y + 4);
    }
  },
};
addEventListener("resize", () => VIEWS[current]?.redraw?.());

/* ------------------------------------------------------------------ Policy */
VIEWS.policy = {
  inited: false, def: "",
  async enter() {
    if (this.inited) return; this.inited = true;
    const p = await policy(); this.def = p.source;
    $("#v-policy").innerHTML = `
      <div class="top"><h1>Policy</h1><span class="sub" id="p-ver"></span>
        <button class="btn" id="p-reset">Revert</button><button class="btn" id="p-test">Test</button><button class="btn" id="p-shadow">Deploy as shadow</button><button class="btn primary" id="p-promote">Promote</button></div>
      <div class="grid split">
        <div class="grid" style="gap:10px"><div class="editor"><div class="gutter" id="gut"></div><textarea id="src" spellcheck="false" aria-label="Policy source"></textarea></div><div class="status" id="p-msg"></div></div>
        <div class="grid" style="align-content:start">
          <div class="card"><div class="card-h"><h2>Kill chains</h2></div><div class="card-b flush" id="p-matrix"><div class="empty">Run Test</div></div></div>
          <div class="card"><div class="card-h"><h2>Rules</h2><span class="sub" id="p-count"></span></div><div class="card-b flush scroll" style="max-height:330px" id="p-rules"></div></div>
        </div>
      </div>`;
    const ta = $("#src"); ta.value = this.def;
    const gut = () => { $("#gut").innerHTML = ta.value.split("\n").map((_, i) => `<span id="ln${i + 1}">${i + 1}</span>`).join("\n"); $("#gut").scrollTop = ta.scrollTop; };
    let t; ta.oninput = () => { gut(); clearTimeout(t); t = setTimeout(() => this.compile(), 500); };
    ta.onscroll = () => $("#gut").scrollTop = ta.scrollTop;
    ta.onkeydown = e => { if (e.key === "Tab") { e.preventDefault(); const s = ta.selectionStart; ta.value = ta.value.slice(0, s) + "  " + ta.value.slice(ta.selectionEnd); ta.selectionStart = ta.selectionEnd = s + 2; } };
    gut();
    $("#p-test").onclick = () => this.test();
    $("#p-reset").onclick = () => { ta.value = this.def; gut(); this.compile(); };
    $("#p-shadow").onclick = async () => { if (!(await this.compile())) return; const r = await post("/api/policy/shadow", { source: ta.value }); toast(`Shadow ${r.shadow.version} is evaluating live traffic`); };
    $("#p-promote").onclick = async () => {
      try { const r = await post("/api/policy/promote"); POLICY = null; this.def = (await policy()).source; this.version(); toast(`Promoted ${r.active}`); }
      catch (e) { toast(e.data?.error === "no shadow policy" ? "Deploy a shadow first" : (e.data?.error || e.message)); }
    };
    this.version(); this.compile();
  },
  async version() { const o = await api("/api/ops"); $("#p-ver").innerHTML = `<span class="mono">${esc(o.policy.active)}</span>${o.policy.shadow ? ` · shadow <span class="mono">${esc(o.policy.shadow.version)}</span>` : ""}`; },
  async compile() {
    $$("#gut .err").forEach(x => x.classList.remove("err"));
    try {
      const r = await post("/api/policy/compile", { source: $("#src").value });
      const mons = r.rules.reduce((a, x) => a + x.monitors.length, 0);
      $("#p-msg").className = "status ok"; $("#p-msg").textContent = `Compiled · ${r.rules.length} rules · ${mons} monitors`;
      $("#p-count").textContent = r.rules.length;
      $("#p-rules").innerHTML = `<table>${r.rules.map(x => `<tr><td><span class="tag">${x.id}</span></td><td>${esc(x.name)}</td><td>${verb(x.action.split(" ")[0])}</td></tr>`).join("")}</table>`;
      return true;
    } catch (e) {
      const d = e.data || {};
      $("#p-msg").className = "status err"; $("#p-msg").textContent = d.error || e.message;
      if (d.line) $("#ln" + d.line)?.classList.add("err");
      return false;
    }
  },
  async test() {
    if (!(await this.compile())) return;
    $("#p-matrix").innerHTML = `<div class="empty">Running</div>`;
    const r = await post("/api/policy/test", { source: $("#src").value });
    $("#p-matrix").innerHTML = `<table>${r.scenarios.map(s => `<tr><td>${esc(s.title)}</td><td style="white-space:nowrap">${s.actions.map(a => `<span class="dot" style="color:var(--${a === "step_up" ? "step" : a})" title="${LABEL[a]}"></span>`).join(" ")}</td>
      <td class="num">${s.stopped_at ? `Step ${s.stopped_at}` : s.id === "family_gift" ? "Passed" : "Missed"}</td></tr>`).join("")}</table>`;
  },
};

/* ------------------------------------------------------------------ Signals */
VIEWS.telemetry = {
  inited: false,
  async enter() {
    if (this.inited) return; this.inited = true;
    const m = await api("/api/meta");
    const tiers = [["device", "On the phone"], ["network", "From the session"], ["telecom", "From telecom feeds"]];
    const feeds = [["TRAI 1600-series", "Registered BFSI service numbers"], ["DoT FRI", "Fraud risk rating per number"], ["DoT MNRL", "Revoked numbers"], ["CAMARA SIM Swap", "Last SIM change, via Airtel, Jio, Vi"], ["CAMARA Number Verification", "SIM in this phone is the registered mobile"]];
    const never = ["Call audio", "Screen contents", "Contact list", "Raw phone numbers", "Full IP address"];
    $("#v-telemetry").innerHTML = `<div class="top"><h1>Signals</h1></div>
      <div class="grid g3">${tiers.map(([t, title]) => `<div class="card"><div class="card-h"><h2>${title}</h2></div><div class="card-b flush"><table>${m.signals.filter(s => s.tier === t).map(s => `
        <tr><td><span class="mono" style="font-size:12.5px">${esc(s.name)}</span><div class="sub" style="font-size:12px">${esc(s.privacy)}</div></td></tr>`).join("")}</table></div></div>`).join("")}</div>
      <div class="grid g2">
        <div class="card"><div class="card-h"><h2>Feeds</h2></div><div class="card-b flush"><table>${feeds.map(([a, b]) => `<tr><td style="font-weight:550">${a}</td><td class="sub">${b}</td></tr>`).join("")}</table></div></div>
        <div class="card"><div class="card-h"><h2>Never collected</h2></div><div class="card-b flush"><table>${never.map(x => `<tr><td>${x}</td><td class="num"><span class="badge block">Never</span></td></tr>`).join("")}</table></div></div>
      </div>`;
  },
};

/* ------------------------------------------------------------------ Benchmark */
VIEWS.bench = {
  d: null,
  async enter() { if (!this.d) this.d = await api("/api/benchmark"); this.render(); },
  redraw() { if (this.d) this.render(); },
  render() {
    const { v1, v2, optin, microbench: mb } = this.d;
    if (!v2) { $("#v-bench").innerHTML = `<div class="empty">No results. Run python -m backend.bench</div>`; return; }
    const A = v2.attacks, B = v2.benign, N = v2.naive_threshold, L = v2.latency_us, C = v2.config;
    const kinds = Object.entries(A.by_kind).filter(([k]) => k.includes("/"));
    $("#v-bench").innerHTML = `
      <div class="top"><h1>Benchmark</h1><span class="sub">${n(C.accounts)} accounts · ${C.days} days · ${n(C.events)} events · ${A.incidents} attacks · seed ${C.seed}</span></div>
      <div class="card compare">
        <div class="hl"><div class="lbl">AgentSnap</div><div class="big">${A.stopped_pct}%</div><small>stopped · ${B.false_hold_pct}% of legitimate actions held</small></div>
        <div><div class="lbl">Policy v1</div><div class="big">${v1 ? v1.attacks.stopped_pct + "%" : "–"}</div><small>stopped · ${v1 ? v1.benign.false_hold_pct + "%" : "–"} held</small></div>
        <div><div class="lbl">Amount limit</div><div class="big" style="color:var(--muted)">${N.stopped_pct}%</div><small>stopped · ${N.false_hold_pct}% held</small></div>
      </div>
      <div class="grid g2">
        <div class="card"><div class="card-h"><h2>Stopped before loss</h2><span class="sub">${money(A.value_stopped)} of ${money(A.value)}</span></div><div class="card-b"><div class="bars">${kinds.map(([k, v]) => `
          <div class="bar"><span>${esc(kind(k.split("/")[0]))} <span class="sub">· ${esc(kind(k.split("/")[1]))}</span></span><div class="track"><div class="fill ${v.stopped_pct < 80 ? "warn" : ""}" style="width:${v.stopped_pct}%"></div></div><b>${v.stopped}/${v.n}</b></div>`).join("")}</div>
          ${optin ? `<p class="sub" style="margin-top:14px">With the opt-in new-beneficiary lock on for seniors with a guardian, the callback variant rises to ${optin.attacks.by_kind["digital_arrest/callback"].stopped_pct}%.</p>` : ""}</div></div>
        <div class="grid">
          <div class="card"><div class="card-h"><h2>False holds by rule</h2><span class="sub">v1 → v2</span></div><div class="card-b flush">${this.fh(v1, v2)}</div></div>
          <div class="metrics"><div class="metric"><span>p50</span><b>${L.p50}<small> µs</small></b></div><div class="metric"><span>p99</span><b>${L.p99}<small> µs</small></b></div><div class="metric"><span>Throughput</span><b>${n(v2.throughput_events_per_s)}</b><small>events/s, one core</small></div></div>
        </div>
      </div>
      ${mb ? `<div class="card"><div class="card-h"><h2>Cost per event vs account history</h2><span class="sub">${mb[mb.length - 1].speedup}× at ${n(mb[mb.length - 1].history)} events</span></div><div class="card-b">${this.chart(mb)}</div></div>` : ""}`;
  },
  fh(v1, v2) {
    if (!v1) return "";
    const ids = [...new Set([...Object.keys(v1.benign.false_hold_rules), ...Object.keys(v2.benign.false_hold_rules)])].sort((a, b) => (v1.benign.false_hold_rules[b] || 0) - (v1.benign.false_hold_rules[a] || 0)).slice(0, 7);
    return `<table><tr><th>Rule</th><th class="num">v1</th><th class="num">v2</th></tr>${ids.map(i => `<tr><td><span class="tag">${i}</span></td><td class="num">${v1.benign.false_hold_rules[i] || 0}</td><td class="num"><b>${v2.benign.false_hold_rules[i] || 0}</b></td></tr>`).join("")}
      <tr><td><b>Total</b></td><td class="num">${v1.benign.false_holds}</td><td class="num"><b>${v2.benign.false_holds}</b></td></tr></table>`;
  },
  chart(mb) {
    const W = 900, H = 220, l = 52, r = 130, t = 12, b = 30;
    const max = Math.max(...mb.map(x => x.reference_us)) * 1.08;
    const X = i => l + i * (W - l - r) / (mb.length - 1), Y = v => H - b - v / max * (H - t - b);
    const path = k => mb.map((x, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(x[k]).toFixed(1)}`).join("");
    const grid = [0, .5, 1].map(f => `<line x1="${l}" x2="${W - r}" y1="${Y(max * f)}" y2="${Y(max * f)}" stroke="var(--line-2)"/><text x="${l - 8}" y="${Y(max * f) + 4}" text-anchor="end">${n(Math.round(max * f))} µs</text>`).join("");
    const last = mb.length - 1;
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Cost per event against history length">${grid}
      <path d="${path("reference_us")}" fill="none" stroke="var(--faint)" stroke-width="2" stroke-dasharray="5 4"/>
      <path d="${path("incremental_us")}" fill="none" stroke="var(--accent)" stroke-width="2.5"/>
      ${mb.map((x, i) => `<circle cx="${X(i)}" cy="${Y(x.incremental_us)}" r="3.5" fill="var(--accent)"/><text x="${X(i)}" y="${H - 8}" text-anchor="middle">${n(x.history)}</text>`).join("")}
      <text x="${X(last) + 10}" y="${Y(mb[last].reference_us) + 4}">Full scan</text>
      <text x="${X(last) + 10}" y="${Y(mb[last].incremental_us) + 4}" class="ink">AgentSnap</text></svg>`;
  },
};

/* ------------------------------------------------------------------ Audit */
VIEWS.audit = {
  async enter(msg = "") {
    const a = await api("/api/audit"), v = a.verify;
    $("#v-audit").innerHTML = `
      <div class="top"><h1>Audit</h1><button class="btn" id="au-verify">Verify</button><button class="btn" id="au-tamper">Edit a record</button><button class="btn danger" id="au-insider">Rewrite history</button></div>
      <div class="callout ${v.ok ? "allow" : "block"}">${icon("shield")}<b>${v.ok ? "Intact" : "Tampered"}</b><span>${n(v.checked)} records${v.ok ? ` · ${v.signed_checkpoints} signed checkpoints` : ` · first bad record #${v.first_bad_seq} · ${esc(v.reason)}`}</span></div>
      ${msg ? `<div class="callout neutral">${esc(msg)}</div>` : ""}
      <div class="card"><div class="card-b flush">${a.tail.length ? `<table><tr><th>#</th><th>BO</th><th>Decision</th><th>Hash</th></tr>${a.tail.map(r => `<tr><td class="mono">${r.seq}</td><td class="id">${esc(r.bo)}</td><td>${LABEL[r.action] ? badge(r.action) : `<span class="badge neutral">${esc(String(r.action).replace(/_/g, " "))}</span>`}</td><td class="id">${esc(r.hash.slice(0, 24))}</td></tr>`).join("")}</table>` : `<div class="empty">Start the live stream</div>`}</div></div>`;
    const pick = a.tail.find(r => r.action === "hold") || a.tail[Math.min(10, a.tail.length - 1)];
    $("#au-verify").onclick = () => this.enter();
    $("#au-tamper").onclick = async () => { if (!pick) return; await post(`/api/audit/tamper/${pick.seq}`); this.enter(`Record #${pick.seq} was changed in the database.`); };
    $("#au-insider").onclick = async () => { if (!pick) return; await post(`/api/audit/tamper/${pick.seq}?recompute=1`); this.enter(`Record #${pick.seq} was changed and every later hash recomputed. The signed checkpoint still disagrees.`); };
  },
};

/* ------------------------------------------------------------------ Operations */
VIEWS.ops = {
  timer: null, drill: null,
  enter() {
    const tick = () => this.render().catch(() => {});   // server away: keep the last view, try again
    tick(); clearInterval(this.timer);
    this.timer = setInterval(() => current === "ops" ? tick() : clearInterval(this.timer), 3000);
  },
  async render() {
    const o = await api("/api/ops"), g = o.gauges, c = o.counters || {}, sh = o.policy.shadow;
    const B = o.latency_us.buckets, maxB = Math.max(1, ...B.map(x => x[1]));
    const d = this.drill;
    $("#v-ops").innerHTML = `
      <div class="top"><h1>Operations</h1><button class="btn" id="op-snap">Snapshot</button><button class="btn primary" id="op-drill">Recovery drill</button></div>
      ${d ? (d.error ? `<div class="callout neutral">${esc(d.error)}</div>` : `<div class="callout ${d.identical ? "allow" : "block"}"><b>${d.identical ? "Recovered" : "Mismatch"}</b><span>${n(d.replayed)} inputs replayed in ${d.ms} ms · fingerprint <span class="mono">${esc(d.digest_restored)}</span></span></div>`) : ""}
      <div class="metrics">
        <div class="metric"><span>Input log</span><b>${n(g.event_log_seq)}</b></div>
        <div class="metric"><span>Audit records</span><b>${n(g.audit_seq)}</b></div>
        <div class="metric"><span>Monitor state</span><b>${n(g.monitor_entries)}</b></div>
        <div class="metric hold"><span>Holds pending</span><b>${n(g.holds_pending)}</b><small>${g.holds_escalated} escalated</small></div>
        <div class="metric"><span>Duplicates · late</span><b>${n(c.duplicate)} · ${n(c.late)}</b></div>
      </div>
      <div class="grid g2">
        <div class="card"><div class="card-h"><h2>Providers</h2></div><div class="card-b flush"><table><tr><th>Provider</th><th>State</th><th class="num">Calls</th><th class="num">Errors</th><th></th></tr>
          ${o.providers.map(p => `<tr><td>${esc(PROVIDER[p.name] || p.name)}</td><td>${p.state === "open" ? `<span class="badge block">Degraded</span>` : `<span class="badge allow">Healthy</span>`}</td>
          <td class="num">${n(p.calls)}</td><td class="num">${n(p.errors)}</td><td class="num"><button class="btn" data-prov="${p.name}" data-st="${p.state === "open" ? "up" : "down"}">${p.state === "open" ? "Restore" : "Fail"}</button></td></tr>`).join("")}</table></div></div>
        <div class="card"><div class="card-h"><h2>Decision latency</h2><span class="sub">p50 ≤ ${o.latency_us.p50_bucket} µs · p99 ≤ ${o.latency_us.p99_bucket} µs</span></div><div class="card-b">
          <div class="hist">${B.map(([, v]) => `<div style="height:${Math.max(2, 100 * v / maxB)}%"></div>`).join("")}</div>
          <div class="hist-l">${B.map(([b]) => `<span>${b === "inf" ? "∞" : b}</span>`).join("")}</div></div></div>
      </div>
      <div class="grid g2">
        <div class="card"><div class="card-h"><h2>Policy versions</h2>${sh ? `<span class="badge accent">Shadow ${esc(sh.version)} · ${sh.disagreement_rate == null ? "0" : (100 * sh.disagreement_rate).toFixed(2)}% disagree</span>` : ""}</div><div class="card-b flush"><table>${o.policy.history.slice().reverse().map((h, i) => `<tr><td class="mono">${esc(h.version)}</td><td class="sub">${{ load: "Initial", promote: "Promoted from shadow" }[h.via] || esc(h.via)}</td><td class="num">${i === 0 ? `<span class="badge allow">Active</span>` : ""}</td></tr>`).join("")}</table></div></div>
        <div class="card"><div class="card-h"><h2>Rule hits</h2></div><div class="card-b flush">${Object.keys(o.rule_hits).length ? `<table>${Object.entries(o.rule_hits).slice(0, 8).map(([k, v]) => `<tr><td><span class="tag">${esc(k)}</span></td><td class="num">${n(v)}</td></tr>`).join("")}</table>` : `<div class="empty">Start the live stream</div>`}</div></div>
      </div>`;
    $("#op-snap").onclick = async () => { const s = await post("/api/ops/snapshot"); this.drill = null; toast(`Snapshot at input ${n(s.event_seq)}`); this.render(); };
    $("#op-drill").onclick = async () => { try { this.drill = await post("/api/ops/drill"); } catch (e) { this.drill = { error: "Take a snapshot, let traffic run, then run the drill." }; } this.render(); };
    $$("[data-prov]").forEach(b => b.onclick = async () => { await post(`/api/ops/provider/${b.dataset.prov}/${b.dataset.st}`); this.render(); });
  },
};

/* boot */
let start = "live";
try { start = INIT_HASH.slice(1).split("-")[0] || localStorage.getItem("as.view") || "live"; } catch (e) {}
show(VIEWS[start] ? start : "live");
