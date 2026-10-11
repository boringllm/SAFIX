"use strict";
const $ = (id) => document.getElementById(id);
const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_CLASS = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
const SEV_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
                    low: "var(--low)", info: "var(--info)" };

let lastResult = null;
let lastInput = "";               // the content that was actually scanned (for export)
let disabledSet = new Set();      // rule/detector ids the user hid
let rulesLoaded = false;

const SAMPLE = [
  "8=FIX.4.4|9=72|35=A|34=1|49=CLIENT|52=20231015-09:00:00.000|56=SERVER|98=0|108=30|10=0|",
  "8=FIX.4.4|35=D|34=2|49=CLIENT|52=20231015-09:00:01.000|56=SERVER|11=O1|55=AAPL|54=1|38=-100|40=2|44=0|60=20231015-09:00:01.000|10=0|",
  "8=FIX.4.4|35=D|34=2|49=CLIENT|52=20231015-09:00:02.000|56=SERVER|11=O1|11=O2|55=AAPL|54=I|38=100|40=2|44=1e5|60=20231015-09:00:02.000|10=0|",
  "8=FIX.4.4|35=B|34=3|49=CLIENT|52=20231015-09:00:03.000|56=SERVER|148=h|58=<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>|10=0|",
].join("\n");

async function init() {
  try { disabledSet = new Set(JSON.parse(localStorage.getItem("safix.disabled") || "[]")); } catch (e) {}
  try { $("version").textContent = "v" + (await (await fetch("/api/health")).json()).version; } catch (e) {}
  try {
    const d = await (await fetch("/api/dictionaries")).json();
    d.versions.forEach(v => { const o = document.createElement("option"); o.value = v; o.textContent = v; $("fixVersion").appendChild(o); });
  } catch (e) {}
  try { buildThresholds((await (await fetch("/api/config/schema")).json()).defaults.thresholds); } catch (e) {}

  document.querySelectorAll(".tab").forEach(t => t.onclick = () => switchView(t.dataset.view));
  $("sampleBtn").onclick = () => { $("content").value = SAMPLE; };
  $("scanBtn").onclick = runScan;
  $("fileInput").onchange = onUpload;
  $("search").oninput = render;
  $("catFilter").onchange = render;
  $("sevFilter").onchange = render;
  $("showSuppressed").onchange = render;
  document.querySelectorAll(".export").forEach(b => b.onclick = () => exportReport(b.dataset.fmt));

  $("saveRules").onclick = saveRules;
  $("reloadRules").onclick = loadCustomRules;
  $("insertExample").onclick = insertExample;
  $("ruleSearch").oninput = renderRuleList;

  $("liveStart").onclick = startLive;
  $("liveStop").onclick = stopLive;
  $("liveClear").onclick = () => { $("liveFindings").innerHTML = ""; liveCount = 0; };
  // mirror dictionary options into the live selector
  const lfx = $("liveFixVersion");
  fetch("/api/dictionaries").then(r => r.json()).then(d =>
    d.versions.forEach(v => { const o = document.createElement("option"); o.value = v; o.textContent = v; lfx.appendChild(o); })).catch(() => {});
}

function switchView(view) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === view));
  $("view-scan").hidden = view !== "scan";
  $("view-live").hidden = view !== "live";
  $("view-rules").hidden = view !== "rules";
  if (view === "rules" && !rulesLoaded) { loadRulesView(); rulesLoaded = true; }
}

/* ---------------- Live view (Server-Sent Events) ---------------- */
let liveSource = null;
let liveCount = 0;

function startLive() {
  const path = $("livePath").value.trim();
  if (!path) { setLiveStatus("Enter a server-side log file path.", "bad"); return; }
  stopLive();
  const qs = new URLSearchParams({ path, from_start: $("liveFromStart").checked,
    severity_min: $("liveSeverity").value });
  if ($("liveFixVersion").value) qs.set("fix_version", $("liveFixVersion").value);
  liveSource = new EventSource("/api/watch/stream?" + qs);
  $("liveStart").disabled = true; $("liveStop").disabled = false;
  setLiveStatus("connecting…", "");

  liveSource.addEventListener("status", e => {
    const d = JSON.parse(e.data);
    if (d.state === "watching") setLiveStatus(`<span class="live-dot"></span>watching ${esc(d.path)}`, "ok");
    else if (d.state === "ended") { setLiveStatus("stream ended (end of file / stopped).", ""); stopLive(); }
  });
  liveSource.addEventListener("error", e => {
    if (e.data) { setLiveStatus("error: " + esc(JSON.parse(e.data).message), "bad"); stopLive(); }
    else if (liveSource && liveSource.readyState === EventSource.CLOSED) { setLiveStatus("disconnected.", "bad"); stopLive(); }
  });
  liveSource.addEventListener("summary", e => renderLiveSummary(JSON.parse(e.data)));
  liveSource.addEventListener("finding", e => addLiveFinding(JSON.parse(e.data)));
}

function stopLive() {
  if (liveSource) { liveSource.close(); liveSource = null; }
  $("liveStart").disabled = false; $("liveStop").disabled = true;
}

function setLiveStatus(html, cls) { const s = $("liveStatus"); s.className = "exmsg " + (cls || ""); s.innerHTML = html; }

function renderLiveSummary(s) {
  const counts = s.counts_by_severity || {};
  const chips = SEV.filter(x => counts[x]).map(x => `<span class="chip ${SEV_CLASS[x]}">${counts[x]} ${x}</span>`).join("");
  $("liveSummary").innerHTML = `
    <div class="sumline"><div class="chips">${chips || '<span class="chip ghost">0 findings</span>'}</div></div>
    <div class="sumline"><span class="meta">${s.messages} messages · ${s.sessions} sessions ·
      ${s.findings} findings total</span></div>`;
}

function addLiveFinding(f) {
  liveCount++;
  const wrap = document.createElement("div");
  wrap.innerHTML = findingCard(f);
  const el = wrap.firstElementChild;
  el.classList.add("live-new");
  const head = el.querySelector(".head");
  head.onclick = () => el.classList.toggle("open");
  const box = $("liveFindings");
  box.insertBefore(el, box.firstChild);     // newest on top
  while (box.children.length > 500) box.removeChild(box.lastChild);
}

function buildThresholds(thr) {
  const box = $("thresholds"); box.innerHTML = "";
  Object.entries(thr).forEach(([k, v]) => {
    const row = document.createElement("div"); row.className = "trow";
    const lab = document.createElement("span"); lab.textContent = k; lab.title = k;
    const inp = document.createElement("input"); inp.type = "number"; inp.step = "any";
    inp.value = v; inp.dataset.key = k;
    row.append(lab, inp); box.appendChild(row);
  });
}

function collectConfig() {
  const cfg = {};
  const fv = $("fixVersion").value; if (fv) cfg.fix_version = fv;
  const d = $("delimiter").value; if (d) cfg.field_delimiter = d;
  cfg.severity_min = $("severityMin").value;
  cfg.dedup = $("dedup").checked;
  const thr = {};
  document.querySelectorAll("#thresholds input").forEach(i => { if (i.value !== "") thr[i.dataset.key] = Number(i.value); });
  if (Object.keys(thr).length) cfg.thresholds = thr;
  const sup = $("suppressions").value.trim();
  if (sup) { try { cfg.suppressions = JSON.parse(sup); } catch (e) {} }
  if (disabledSet.size) cfg.disabled_rules = [...disabledSet];
  return cfg;
}

async function runScan() {
  const content = $("content").value;
  if (!content.trim()) { $("summary").innerHTML = '<p class="err">Nothing to scan — paste a FIX log or load the sample.</p>'; return; }
  $("scanBtn").disabled = true; $("scanBtn").textContent = "Scanning…";
  try {
    const res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, config: collectConfig() }) });
    lastResult = await res.json(); lastInput = content;
    populateFilters(lastResult); render();
  } catch (e) { $("summary").innerHTML = '<p class="err">Scan failed: ' + e + "</p>"; }
  finally { $("scanBtn").disabled = false; $("scanBtn").textContent = "Scan"; }
}

async function onUpload(ev) {
  const file = ev.target.files[0]; if (!file) return;
  const fd = new FormData(); fd.append("file", file);
  const fv = $("fixVersion").value, d = $("delimiter").value;
  const qs = new URLSearchParams(); if (fv) qs.set("fix_version", fv); if (d) qs.set("delimiter", d);
  $("scanBtn").disabled = true;
  try {
    const res = await fetch("/api/scan/upload?" + qs, { method: "POST", body: fd });
    lastResult = await res.json();
    lastInput = lastResult.content || "";
    if (lastResult.content) $("content").value = lastResult.content;
    populateFilters(lastResult); render();
  } finally { $("scanBtn").disabled = false; }
}

function populateFilters(r) {
  const cats = [...new Set(r.findings.map(f => f.category))].sort();
  const sel = $("catFilter"); sel.innerHTML = '<option value="">all categories</option>';
  cats.forEach(c => { const o = document.createElement("option"); o.value = c; o.textContent = c; sel.appendChild(o); });
  $("filters").hidden = false;
}

function render() {
  if (!lastResult) return;
  const r = lastResult, counts = r.counts_by_severity || {}, fmt = r.detected_format || {};
  const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
  const chips = SEV.filter(s => counts[s]).map(s => `<span class="chip ${SEV_CLASS[s]}">${counts[s]} ${s}</span>`).join("");
  const bar = SEV.filter(s => counts[s]).map(s => `<span style="background:${SEV_COLOR[s]};flex:${counts[s]}"></span>`).join("");
  $("summary").innerHTML = `
    <div class="sumline"><div class="chips">${chips || '<span class="chip ghost">0 findings</span>'}</div></div>
    <div class="bar">${bar}</div>
    <div class="sumline"><span class="meta">${r.message_count} messages · ${r.session_count} sessions ·
      format ${fmt.input_kind || "?"} · delimiter ${JSON.stringify(fmt.field_delimiter || "")}</span></div>`;

  const q = $("search").value.toLowerCase(), cat = $("catFilter").value, sev = $("sevFilter").value;
  const showSup = $("showSuppressed").checked;
  const rows = r.findings.filter(f => {
    if (f.suppressed && !showSup) return false;
    if (cat && f.category !== cat) return false;
    if (sev && f.severity !== sev) return false;
    if (q) { const hay = (f.rule_id + " " + f.title + " " + (f.session || "") + " " + (f.vector_ids || []).join(" ") + " " + f.message).toLowerCase(); if (!hay.includes(q)) return false; }
    return true;
  });
  const box = $("findings");
  if (!rows.length) { box.innerHTML = total ? '<p class="meta">No findings match the filter.</p>' : '<p class="none">No findings.</p>'; return; }
  box.innerHTML = rows.map(findingCard).join("");
  box.querySelectorAll(".finding .head").forEach(h => h.onclick = () => h.parentElement.classList.toggle("open"));
}

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

function findingCard(f) {
  const loc = [f.session, f.msg_seq != null ? "seq " + f.msg_seq : "", f.source_line != null ? "line " + f.source_line : ""].filter(Boolean).join(" · ");
  const occ = f.occurrence_count > 1 ? ` ×${f.occurrence_count}` : "";
  const benign = (f.benign_notes || []).map(b => `<li>${esc(b)}</li>`).join("");
  const regs = (f.regulatory_refs || []).join(", ");
  return `<div class="finding ${f.suppressed ? "suppressed" : ""}">
    <div class="head">
      <span class="chip ${SEV_CLASS[f.severity]}">${f.severity.toUpperCase()}</span>
      <span class="chip ghost">conf ${f.confidence}</span>
      <span class="rule">${esc(f.rule_id)}</span><span>${esc(f.title)}${occ}</span>
      <span class="pri">P${f.priority}</span>
    </div>
    <div class="body">
      <p class="msg">${esc(f.message)}</p>
      <div class="kv">
        <span class="k">Category</span><span>${esc(f.category)}</span>
        <span class="k">MsgType</span><span>${esc(f.msg_type)}</span>
        <span class="k">Location</span><span>${esc(loc)}</span>
        <span class="k">Tag</span><span>${esc(f.tag)}</span>
        <span class="k">Vectors</span><span>${esc((f.vector_ids || []).join(", "))}</span>
        ${regs ? `<span class="k">Regulatory</span><span>${esc(regs)}</span>` : ""}
        ${f.suppressed ? `<span class="k">Suppressed</span><span>${esc(f.suppressed_by)}</span>` : ""}
      </div>
      ${f.evidence ? `<pre class="evidence">${esc(f.evidence)}</pre>` : ""}
      ${f.remediation ? `<div class="remed"><b>Remediation:</b> ${esc(f.remediation)}</div>` : ""}
      ${benign ? `<div class="benign"><b>Benign explanations:</b><ul>${benign}</ul></div>` : ""}
    </div></div>`;
}

async function exportReport(fmt) {
  const msg = $("exportMsg");
  const content = lastInput || $("content").value;
  if (!content.trim()) { msg.className = "exmsg bad"; msg.textContent = "Run a scan first (or paste a log), then download."; return; }
  msg.className = "exmsg"; msg.textContent = "Preparing " + fmt.toUpperCase() + "…";
  try {
    const res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, config: collectConfig(), report: fmt }) });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const blob = await res.blob();
    const ext = { sarif: "sarif", json: "json", html: "html", junit: "xml" }[fmt];
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "safix-report." + ext;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    msg.className = "exmsg ok"; msg.textContent = "Downloaded safix-report." + ext;
  } catch (e) { msg.className = "exmsg bad"; msg.textContent = "Export failed: " + e; }
}

/* ---------------- Rules view ---------------- */
async function loadRulesView() {
  await loadCustomRules();
  await loadHelp();
  await loadAllRules();
}

async function loadCustomRules() {
  try { $("customRules").value = (await (await fetch("/api/rules/custom")).json()).yaml || ""; } catch (e) {}
}

async function saveRules() {
  const st = $("rulesStatus");
  st.className = "exmsg"; st.textContent = "Saving…";
  try {
    const res = await fetch("/api/rules/custom", { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ yaml: $("customRules").value }) });
    const r = await res.json();
    if (r.ok) { st.className = "exmsg ok"; st.textContent = `Saved ${r.count} custom rule(s). They now apply to every scan.`; await loadAllRules(); }
    else { st.className = "exmsg bad"; st.textContent = "Invalid: " + r.error; }
  } catch (e) { st.className = "exmsg bad"; st.textContent = "Save failed: " + e; }
}

let helpExample = "";
async function loadHelp() {
  try {
    const h = await (await fetch("/api/rules/help")).json();
    helpExample = h.example || "";
    $("helpExample").textContent = helpExample;
    $("opsTable").innerHTML = h.operators.map(o =>
      `<tr><td>${esc(o.op)}</td><td>${esc(o.desc)}<br><span class="meta">${esc(o.example)}</span></td></tr>`).join("");
  } catch (e) {}
}

function insertExample() {
  const ta = $("customRules");
  ta.value = (ta.value.trim() ? ta.value.replace(/\s+$/, "") + "\n" : "") + (helpExample || "");
}

let allRules = { detectors: [], catalog: [], custom: [] };
async function loadAllRules() {
  try { allRules = await (await fetch("/api/rules/all")).json(); } catch (e) {}
  renderRuleList();
}

function renderRuleList() {
  const q = $("ruleSearch").value.toLowerCase();
  const box = $("ruleList");
  const groups = [
    ["Detectors (coarse — disables a whole detector)", allRules.detectors.map(d => ({ id: d.id, category: d.category, title: d.title }))],
    ["Custom rules", allRules.custom.map(r => ({ id: r.id, category: r.category, title: r.title, severity: r.severity }))],
    ["Built-in rules", allRules.catalog.map(r => ({ id: r.id, category: r.category, title: r.title, severity: r.severity }))],
  ];
  let html = "";
  for (const [label, items] of groups) {
    const rows = items.filter(it => !q || (it.id + " " + it.title + " " + it.category).toLowerCase().includes(q));
    if (!rows.length) continue;
    html += `<div class="rules-group">${esc(label)}</div>`;
    html += rows.map(it => {
      const off = disabledSet.has(it.id);
      const sev = it.severity ? `<span class="sev" style="background:${SEV_COLOR[it.severity] || "var(--info)"}">${it.severity}</span>` : "";
      return `<label class="rule-row ${off ? "off" : ""}">
        <input type="checkbox" data-id="${esc(it.id)}" ${off ? "" : "checked"}>
        <span class="rid">${esc(it.id)}</span> ${sev}
        <span>${esc(it.title || "")}</span>
        <span class="rsrc">${esc(it.category)}</span></label>`;
    }).join("");
  }
  box.innerHTML = html || '<p class="meta">No rules match.</p>';
  box.querySelectorAll("input[type=checkbox]").forEach(cb => cb.onchange = () => {
    const id = cb.dataset.id;
    if (cb.checked) disabledSet.delete(id); else disabledSet.add(id);
    localStorage.setItem("safix.disabled", JSON.stringify([...disabledSet]));
    cb.closest(".rule-row").classList.toggle("off", !cb.checked);
  });
}

init();
