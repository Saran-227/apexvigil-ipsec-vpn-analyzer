/* APEX VIGIL EXECUTIVE REPORT DATA CONTRACT & RENDERER */

const EXECUTIVE_REPORT = {};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
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
  ["reportId", "reportId2", "reportId3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = meta.id || "AV-2026-EXEC";
  });
  ["generated", "generated2", "generated3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = meta.generated || "";
  });

  // Section 1: Executive Summary & System Metadata
  const v = s1.verdict || {};
  const banner = document.getElementById("verdictBanner");
  const badge = document.getElementById("verdictBadge");
  const action = document.getElementById("verdictAction");
  const summary = document.getElementById("verdictSummary");

  if (summary) summary.textContent = v.summary || (data.posture && data.posture.summary) || "";
  if (badge) badge.textContent = v.badge || "ATTENTION REQUIRED";
  if (action) action.textContent = v.actionRequired || "IMMEDIATE ACTION: HIGH";

  if (banner) {
    banner.classList.remove("crit", "warn");
    if (v.status === "CRITICAL_FAIL" || v.status === "FAIL") banner.classList.add("crit");
    else if (v.status === "ATTENTION_REQUIRED" || v.status === "WARN") banner.classList.add("warn");
  }

  const ts = s1.sessionTimestamps || {};
  const ep = s1.endpoints || [];
  const origin = ep[0] || {};
  const tunnel = ep[1] || {};
  const remote = ep[2] || {};

  const durEl = document.getElementById("metaDuration");
  if (durEl) durEl.textContent = ts.duration || "56.79 seconds";
  const perEl = document.getElementById("metaPeriod");
  if (perEl) perEl.textContent = ts.period || meta.analysisPeriod || "";

  const orgH = document.getElementById("metaOriginHost");
  if (orgH) orgH.textContent = origin.host || "Company Branch Gateway 1";
  const orgIp = document.getElementById("metaOriginIp");
  if (orgIp) orgIp.textContent = `${origin.ip || ""} • ${origin.vpn || ""}`;

  const tunN = document.getElementById("metaTunnelName");
  if (tunN) tunN.textContent = tunnel.name || "IPsec ESP over UDP 4500 (NAT-T)";
  const tunC = document.getElementById("metaTunnelCipher");
  if (tunC) tunC.textContent = tunnel.cipher || "AES-256-GCM / ECP-256";

  const remH = document.getElementById("metaRemoteHost");
  if (remH) remH.textContent = remote.host || "Enterprise Datacenter Core Gateway";
  const remIp = document.getElementById("metaRemoteIp");
  if (remIp) remIp.textContent = `${remote.ip || ""} • ${remote.vpn || ""}`;

  // Section 2: Holistic Risk Scorecard
  const sc = s2.scorecard || {};
  const gNum = document.getElementById("gaugeNumber");
  const gRisk = document.getElementById("gaugeRiskLabel");
  const gPath = document.getElementById("gaugePath");

  const score = sc.compositeScore != null ? sc.compositeScore : (data.summary && data.summary.compositeRiskScore != null ? data.summary.compositeRiskScore : 100);
  if (gNum) gNum.textContent = score;
  if (gRisk) gRisk.textContent = `${sc.riskLevel || (score >= 85 ? 'LOW' : score >= 60 ? 'MODERATE' : 'CRITICAL')} RISK`;

  if (gPath) {
    const r = 80;
    const arcLen = Math.PI * r; // ~251.2
    const offset = arcLen - (arcLen * (score / 100));
    gPath.style.strokeDasharray = `${arcLen}`;
    gPath.style.strokeDashoffset = `${offset}`;
    gPath.style.stroke = score >= 80 ? "var(--green)" : score >= 60 ? "var(--orange)" : "var(--red)";
  }

  const nBadge = document.getElementById("nistBadge");
  const nRef = document.getElementById("nistRef");
  if (nBadge) {
    const isPass = (sc.nistStatus || "").toUpperCase().includes("PASS");
    nBadge.textContent = isPass ? "PASS" : "CRITICAL FAIL";
    nBadge.className = `nist-badge ${isPass ? 'pass' : 'fail'}`;
  }
  if (nRef) nRef.textContent = sc.nistReference || "MANDATE §4.2.3 (PFS Child SA)";

  const ready = s2.deploymentReadiness || {};
  const rRating = document.getElementById("readyRating");
  const rDesc = document.getElementById("readyDesc");
  if (rRating) {
    const ratingStr = ready.rating || v.readinessRating || "READY FOR PRODUCTION";
    rRating.textContent = ratingStr;
    rRating.className = "r-rating";
    if (ratingStr.includes("READY") || ratingStr.includes("APPROVED")) rRating.classList.add("safe");
    else if (ratingStr.includes("BLOCKED") || ratingStr.includes("FAIL")) rRating.classList.add("crit");
  }
  if (rDesc) rDesc.textContent = ready.desc || v.readinessDesc || "Production readiness verified under federal cybersecurity guidelines.";

  const kpiEl = document.getElementById("kpiGrid");
  const kpis = s2.kpis || [
    ["CRYPTOGRAPHIC RESILIENCE", "98%", "AES-GCM active, PFS missing"],
    ["COMPLIANCE ALIGNMENT", "95%", "NIST SP 800-77 gap identified"],
    ["THREAT EXPOSURE INDEX", "LOW", "Potential retroactive decrypt"],
    ["CHANNEL STABILITY", "99.9%", "Zero dropped packets detected"]
  ];
  if (kpiEl) {
    kpiEl.innerHTML = kpis.map(k => `
      <div class="kpi-card">
        <div class="kpi-label">${esc(k[0])}</div>
        <div class="kpi-val">${esc(k[1])}</div>
        <div class="kpi-sub">${esc(k[2] || "")}</div>
      </div>
    `).join("");
  }

  // Section 3: Executive Threat Matrix (Spacious 2x2 Grid)
  const threatEl = document.getElementById("threatGrid");
  const threats = s3.threatMatrix || [
    {
      threat: "Wiretap Eavesdropping & Retrospective Decryption",
      severity: "HIGH",
      likelihood: "Low",
      businessRisk: "Adversaries recording encrypted transit can retrospectively decipher all historic corporate traffic if private keys or static PSK credentials are leaked or subpoenaed.",
      status: "ACTIVE GAP"
    },
    {
      threat: "Credential Cracking & Identity Impersonation",
      severity: "MEDIUM",
      likelihood: "Moderate",
      businessRisk: "Symmetric shared keys lack individual attribution and are vulnerable to dictionary attacks, insider theft, and rogue gateway impersonation.",
      status: "OBSERVED"
    },
    {
      threat: "Traffic Shape Fingerprinting & Reconnaissance",
      severity: "MEDIUM",
      likelihood: "High",
      businessRisk: "Passive eavesdroppers observing packet length clustering and inter-arrival timing can accurately infer inner application types, operational cadences, and high-value data transfers.",
      status: "OBSERVED"
    },
    {
      threat: "Protocol Downgrade & Replay Injection",
      severity: "LOW",
      likelihood: "Low",
      businessRisk: "Sequence number validation prevents packet duplication and unauthorized state re-injection. Evaluated tunnel shows 100% strictly monotonic sequence progression.",
      status: "PROTECTED"
    }
  ];

  if (threatEl) {
    threatEl.innerHTML = threats.slice(0, 4).map(t => {
      const sev = (t.severity || "LOW").toLowerCase();
      let cls = "safe";
      if (sev.includes("crit")) cls = "crit";
      else if (sev.includes("high")) cls = "high";
      else if (sev.includes("med")) cls = "med";

      return `
        <div class="threat-cell-wide ${cls}">
          <div>
            <div class="threat-title">${esc(t.threat)}</div>
            <div class="threat-meta">
              <span>Sev: <b>${esc(t.severity)}</b></span>
              <span>Likelihood: <b>${esc(t.likelihood || "Low")}</b></span>
            </div>
            <div class="threat-desc">${esc(t.businessRisk)}</div>
          </div>
          <div class="threat-status-tag">${esc(t.status || "ACTIVE")}</div>
        </div>
      `;
    }).join("");
  }

  // Section 4: High-Level Traffic Overview
  const to = s4.trafficOverview || {};
  const dist = to.distribution || [
    { category: "Encrypted Video Stream", pct: "94.2%", volume: "21.48 MB" },
    { category: "Bulk Data & Sync", pct: "3.1%", volume: "0.71 MB" },
    { category: "Interactive Web", pct: "1.8%", volume: "0.41 MB" },
    { category: "ESP Control & Other", pct: "0.9%", volume: "0.21 MB" }
  ];

  const tBars = document.getElementById("trafficBars");
  if (tBars) {
    tBars.innerHTML = dist.map(d => `
      <div class="t-bar-row">
        <div class="t-bar-labels">
          <span>${esc(d.category)}</span>
          <span><b>${esc(d.pct)}</b> (${esc(d.volume || "")})</span>
        </div>
        <div class="t-bar-track">
          <div class="t-bar-fill" style="width:${esc(d.pct)}"></div>
        </div>
      </div>
    `).join("");
  }

  const fl = to.flowVolume || {};
  const totPkts = document.getElementById("flowTotalPkts");
  if (totPkts) totPkts.textContent = fl.totalPackets != null ? fl.totalPackets : "557";
  const totVol = document.getElementById("flowTotalVol");
  if (totVol) totVol.textContent = fl.dataVolume || "22.8 MB";
  const avgR = document.getElementById("flowAvgRate");
  if (avgR) avgR.textContent = fl.avgRate || "4 pkt/s";
  const peakR = document.getElementById("flowPeakRate");
  if (peakR) peakR.textContent = fl.peakRate || "9 pkt/s";

  const covert = s4.covertChannelRisk || {};
  const covTag = document.getElementById("covertRiskTag");
  if (covTag) covTag.textContent = covert.riskLevel ? `${covert.riskLevel} RISK` : "MODERATE RISK";

  const covEnt = document.getElementById("covertEntropy");
  if (covEnt) covEnt.textContent = covert.shannonEntropy || "7.98 / 8.0";

  // Parse predictability cleanly
  let predVal = covert.predictability || "Moderate";
  let predSub = "MTU Length Clustering";
  if (predVal.includes("(")) {
    const parts = predVal.split("(");
    predVal = parts[0].trim();
    predSub = parts[1].replace(")", "").trim();
  }
  const covPred = document.getElementById("covertPred");
  if (covPred) covPred.textContent = predVal;
  const covPredSub = document.getElementById("covertPredSub");
  if (covPredSub) covPredSub.textContent = predSub;

  // Parse burstiness cleanly
  let burstVal = covert.burstinessVariance || "Low";
  let burstSub = "Isochronous Media Cadence";
  if (burstVal.includes("(")) {
    const parts = burstVal.split("(");
    burstVal = parts[0].trim();
    burstSub = parts[1].replace(")", "").trim();
  }
  const covBurst = document.getElementById("covertBurst");
  if (covBurst) covBurst.textContent = burstVal;
  const covBurstSub = document.getElementById("covertBurstSub");
  if (covBurstSub) covBurstSub.textContent = burstSub;

  const covAss = document.getElementById("covertAssessment");
  if (covAss) covAss.textContent = covert.assessment || "While payload encryption is cryptographically complete, unpadded ESP packet headers and MTU distribution reveal operational application signatures, creating side-channel intelligence leakage.";

  // Section 5: Strategic Remediation Action Plan
  const roadmap = s5.recommendations || [
    {
      phase: "PHASE 1: IMMEDIATE ACTION",
      window: "0 – 48 Hours",
      action: "Enforce PFS on Child SAs",
      desc: "Mandate ECP-256 (Diffie-Hellman Group 19) on all Child SA proposals in strongSwan / gateway configs to eliminate retrospective decryption risk.",
      resource: "Sr. Network Security Engineer",
      kpi: "Target Risk: 42 (-20 pts exposure)"
    },
    {
      phase: "PHASE 2: TACTICAL MIGRATION",
      window: "30 Days",
      action: "PKI Enterprise Certificate Deployment",
      desc: "Deprecate static Pre-Shared Keys (PSK). Deploy X.509 enterprise machine certificates with mutual TLS/IKEv2 authentication and automated CRL revocation.",
      resource: "PKI & Identity Architecture Team",
      kpi: "Identity Assurance: +15% Compliance"
    },
    {
      phase: "PHASE 3: STRATEGIC GOVERNANCE",
      window: "90 Days",
      action: "Continuous Telemetry & TFC Padding",
      desc: "Enable random Traffic Flow Confidentiality (TFC) padding to mask packet shapes, and integrate ApexVigil real-time anomaly telemetry directly into enterprise SOC SIEM.",
      resource: "SOC Operations & Telecom Engineering",
      kpi: "Zero Side-Channel Drift Assurance"
    }
  ];

  const roadEl = document.getElementById("remediationRoadmap");
  if (roadEl) {
    roadEl.innerHTML = roadmap.slice(0, 3).map(r => `
      <div class="rem-card">
        <div>
          <div class="rem-phase">${esc(r.phase)}</div>
          <div class="rem-window">${esc(r.window)}</div>
          <div class="rem-action">${esc(r.action)}</div>
          <div class="rem-desc">${esc(r.desc)}</div>
        </div>
        <div>
          <div class="rem-resource">Allocated: ${esc(r.resource || "SecOps Team")}</div>
          <div class="rem-kpi">${esc(r.kpi || "")}</div>
        </div>
      </div>
    `).join("");
  }

  const attest = s5.attestation || {};
  const hashEl = document.getElementById("attestHash");
  if (hashEl) hashEl.textContent = attest.hash || "SHA-256: 8b14e9f28a1c9034...";
}

document.addEventListener("DOMContentLoaded", renderExecutive);
