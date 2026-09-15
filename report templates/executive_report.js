/* APEX VIGIL EXECUTIVE REPORT DATA CONTRACT & RENDERER */

const EXECUTIVE_REPORT = {};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
const clip = (v, n) => { const s = String(v ?? ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; };
const words = (v, n) => String(v ?? "").trim().split(/\s+/).filter(Boolean).slice(0, n).join(" ");

function renderExecutive() {
  const data = EXECUTIVE_REPORT || {};
  const meta = data.meta || {};
  const s1 = data.section1 || {};
  const s2 = data.section2 || {};
  const s3 = data.section3 || {};
  const s4 = data.section4 || {};
  const s5 = data.section5 || {};

  // Headers
  ["reportId", "reportId2"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(meta.id || "AV-2026-EXEC", 32);
  });
  ["generated", "generated2"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(meta.generated || "", 32);
  });

  // Section 1: Executive Summary & System Metadata
  const v = s1.verdict || {};
  const banner = document.getElementById("verdictBanner");
  const badge = document.getElementById("verdictBadge");
  const action = document.getElementById("verdictAction");
  const summary = document.getElementById("verdictSummary");

  if (summary) summary.textContent = words(v.summary || (data.posture && data.posture.summary) || "", 65);
  if (badge) {
    badge.textContent = clip(v.badge || "ATTENTION REQUIRED", 28);
    badge.className = `verdict-badge ${v.statusClass || "high"}`;
  }
  if (action) {
    action.textContent = `IMMEDIATE ACTION: ${v.actionRequired || "YES · HIGH"}`;
    action.className = `verdict-action ${v.statusClass || "high"}`;
  }
  if (banner) {
    banner.className = `sec1-summary-banner ${v.statusClass || "high"}`;
  }

  // Metadata Grid
  const ts = s1.timestamps || {};
  const ep = s1.endpoints || [];
  const origin = ep[0] || {};
  const tunnel = ep[1] || {};
  const remote = ep[2] || {};

  const durEl = document.getElementById("metaDuration");
  if (durEl) durEl.textContent = clip(ts.duration || "56.79 sec", 24);
  const perEl = document.getElementById("metaPeriod");
  if (perEl) perEl.textContent = clip(ts.period || meta.analysisPeriod || "", 38);

  const orgH = document.getElementById("metaOriginHost");
  if (orgH) orgH.textContent = clip(origin.host || "Branch Gateway 1", 28);
  const orgIp = document.getElementById("metaOriginIp");
  if (orgIp) orgIp.textContent = clip(`${origin.ip || ""} · ${origin.vpn || ""}`, 36);

  const tunN = document.getElementById("metaTunnelName");
  if (tunN) tunN.textContent = clip(tunnel.tunnel || "IPsec Tunnel Mode", 32);
  const tunC = document.getElementById("metaTunnelCipher");
  if (tunC) tunC.textContent = clip(tunnel.cipher || "AES-256-GCM / ECP-256", 36);

  const remH = document.getElementById("metaRemoteHost");
  if (remH) remH.textContent = clip(remote.host || "Enterprise Datacenter Core", 28);
  const remIp = document.getElementById("metaRemoteIp");
  if (remIp) remIp.textContent = clip(`${remote.ip || ""} · ${remote.vpn || ""}`, 36);

  // Section 2: Holistic Risk Scorecard
  const score = Math.max(0, Math.min(100, Number(s2.score != null ? s2.score : (data.risk && data.risk.final)) || 70));
  const arc = document.getElementById("gaugeArc");
  if (arc) {
    arc.style.strokeDasharray = `${score} 100`;
    if (score < 50) arc.style.stroke = "#b73737";
    else if (score < 80) arc.style.stroke = "#c95b17";
    else arc.style.stroke = "#2e9b70";
  }
  const num = document.getElementById("gaugeNumber");
  if (num) num.textContent = score;
  const riskLbl = document.getElementById("gaugeRisk");
  if (riskLbl) {
    const rTxt = s2.riskLevel || (score < 50 ? "CRITICAL RISK" : (score < 80 ? "HIGH RISK" : "LOW RISK"));
    riskLbl.textContent = rTxt;
    riskLbl.style.color = (score < 50) ? "#b73737" : (score < 80 ? "#c95b17" : "#2e9b70");
  }

  // NIST Badge & Readiness
  const nist = s2.nistCompliance || {};
  const nistEl = document.getElementById("nistBadge");
  if (nistEl) {
    const isPass = (nist.status === "PASS");
    nistEl.textContent = isPass ? "PASS" : "CRITICAL FAIL";
    nistEl.className = isPass ? "nist-badge pass" : "nist-badge fail";
  }

  const ready = s2.readiness || {};
  const readyR = document.getElementById("readinessRating");
  if (readyR) {
    readyR.textContent = clip(ready.rating || v.readinessRating || "CONDITIONAL DEPLOYMENT", 26);
    if ((ready.rating || "").includes("PROD") || (ready.rating || "").includes("READY")) {
      readyR.className = "r-rating safe";
    } else if ((ready.rating || "").includes("BLOCK") || (ready.rating || "").includes("CRIT")) {
      readyR.className = "r-rating crit";
    } else {
      readyR.className = "r-rating";
    }
  }
  const readyD = document.getElementById("readinessDesc");
  if (readyD) readyD.textContent = clip(ready.desc || v.readinessDesc || "", 65);

  // KPIs
  const kpiGrid = document.getElementById("kpiGrid");
  const kpis = s2.kpis || data.kpis || [];
  if (kpiGrid) {
    kpiGrid.innerHTML = kpis.slice(0, 4).map(k => `
      <div class="kpi-card">
        <div class="kpi-label">${esc(clip(k[0], 24))}</div>
        <div class="kpi-val">${esc(clip(k[1], 14))}</div>
        <div class="kpi-sub">${esc(clip(k[2], 32))}</div>
      </div>
    `).join("");
  }

  // Section 3: Executive Threat Matrix
  const threatGrid = document.getElementById("threatGrid");
  const threats = s3.threats || (data.threats || []).map(t => ({
    threat: t[0],
    severity: t[1],
    likelihood: (t[2] || "").split("|")[0] || "",
    impact: (t[2] || "").split("|")[1] || "",
    businessRisk: t[3],
    status: t[4],
    statusClass: String(t[1] || "").toLowerCase()
  }));

  if (threatGrid) {
    threatGrid.innerHTML = threats.slice(0, 4).map(t => {
      const sCls = String(t.statusClass || t.severity || "med").toLowerCase();
      return `
        <div class="threat-cell ${sCls}">
          <div class="threat-title">${esc(clip(t.threat, 32))}</div>
          <div class="threat-meta">
            <span>Sev: ${esc(t.severity || "MED")}</span>
            <span>${esc(clip(t.likelihood || "", 14))}</span>
          </div>
          <div class="threat-desc">${esc(clip(t.businessRisk, 125))}</div>
          <span class="threat-status-tag">${esc(clip(t.status || "ACTIVE", 16))}</span>
        </div>
      `;
    }).join("");
  }

  // Section 4: High-Level Traffic Overview
  const dist = s4.distribution || [
    { category: "Encrypted Video Stream", pct: 94.2, volume: "21.5 MB" },
    { category: "Bulk Data Transfer", pct: 3.1, volume: "0.7 MB" },
    { category: "Interactive Web", pct: 1.8, volume: "0.4 MB" },
    { category: "Control & Other", pct: 0.9, volume: "0.2 MB" }
  ];
  const tBars = document.getElementById("trafficBars");
  if (tBars) {
    tBars.innerHTML = dist.slice(0, 4).map(d => `
      <div class="t-bar-row">
        <div class="t-bar-labels">
          <span>${esc(clip(d.category, 26))}</span>
          <span>${d.pct}% (${esc(d.volume || "")})</span>
        </div>
        <div class="t-bar-track">
          <div class="t-bar-fill" style="width:${Math.max(2, Math.min(100, Number(d.pct) || 0))}%;"></div>
        </div>
      </div>
    `).join("");
  }

  const fm = s4.flowMetrics || {};
  const fMini = document.getElementById("flowMiniStats");
  if (fMini) {
    fMini.innerHTML = `
      <div class="f-mini"><div class="f-lbl">TOTAL PACKETS</div><div class="f-val">${esc(fm.totalPackets || "24,108")}</div></div>
      <div class="f-mini"><div class="f-lbl">DATA VOLUME</div><div class="f-val">${esc(fm.totalVolume || "22.8 MB")}</div></div>
      <div class="f-mini"><div class="f-lbl">AVG RATE</div><div class="f-val">${esc(fm.avgRate || "424 pkt/s")}</div></div>
      <div class="f-mini"><div class="f-lbl">PEAK RATE</div><div class="f-val">${esc(fm.peakRate || "1,120 pkt/s")}</div></div>
    `;
  }

  const covert = s4.covertChannel || {};
  const covTag = document.getElementById("covertTag");
  if (covTag) {
    covTag.textContent = clip(covert.riskLevel ? `${covert.riskLevel} RISK` : "MODERATE RISK", 18);
  }
  const covEnt = document.getElementById("covertEntropy");
  if (covEnt) covEnt.textContent = `${covert.entropy || 7.98} / ${covert.entropyMax || 8.0}`;
  const covPred = document.getElementById("covertPredictability");
  if (covPred) covPred.textContent = clip(covert.predictability || "Moderate", 18);
  const covBurst = document.getElementById("covertBurstiness");
  if (covBurst) covBurst.textContent = clip(covert.burstinessVariance || "Low", 18);
  const covAss = document.getElementById("covertAssessment");
  if (covAss) covAss.textContent = clip(covert.assessment || "", 140);

  // Section 5: Strategic Remediation Action Plan
  const roadmap = s5.recommendations || (data.roadmap || []).map(r => ({
    phase: r[0],
    window: r[1],
    action: r[2],
    desc: r[3],
    kpi: r[4],
    resource: "SecOps Engineering Team"
  }));
  const roadEl = document.getElementById("remediationRoadmap");
  if (roadEl) {
    roadEl.innerHTML = roadmap.slice(0, 3).map(r => `
      <div class="rem-card">
        <div class="rem-phase">${esc(clip(r.phase, 24))}</div>
        <div class="rem-window">${esc(clip(r.window, 18))}</div>
        <div class="rem-action">${esc(clip(r.action, 28))}</div>
        <div class="rem-desc">${esc(clip(r.desc, 130))}</div>
        <div class="rem-resource">Allocated: ${esc(clip(r.resource || "", 30))}</div>
        <div class="rem-kpi">${esc(clip(r.kpi || "", 32))}</div>
      </div>
    `).join("");
  }

  const attest = s5.attestation || {};
  const hashEl = document.getElementById("attestHash");
  if (hashEl) hashEl.textContent = clip(attest.hash || "SHA-256: 8b14e9f2...", 24);
}

document.addEventListener("DOMContentLoaded", renderExecutive);
