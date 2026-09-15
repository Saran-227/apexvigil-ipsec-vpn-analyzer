/* APEX VIGIL EXECUTIVE REPORT DATA CONTRACT
   Ollama returns values only. It never controls HTML/CSS/presentation.
   Hard limits: summary 55 words, KPIs 4, threats 4, trend points 50,
   compliance rows 4, roadmap items 3. */

const EXECUTIVE_REPORT = {
  meta: {
    id: "AV-2026-EXEC-001",
    generated: "15 September 2026",
    capture: "sih26-asim-golden.pcap",
    analysisPeriod: "15 Sep 2026 | 01:21:06 – 01:22:03"
  },
  posture: {
    status: "ATTENTION REQUIRED",
    actionRequired: "YES · HIGH",
    summary: "The evaluated IPsec VPN deployment demonstrates robust data confidentiality via AES-256-GCM encryption. However, Perfect Forward Secrecy (PFS) is disabled on subsequent Child SAs. While no active compromise is detected, historical communications remain at risk if long-term credentials are ever breached. Remediation is advised within 48 hours."
  },
  risk: {
    final: 62,
    level: "HIGH"
  },
  kpis: [
    ["Cryptographic Resilience", "74%", "AES-GCM active, PFS missing"],
    ["Compliance Alignment", "78%", "NIST SP 800-77 gap identified"],
    ["Threat Exposure Index", "MODERATE", "Potential retroactive decrypt"],
    ["Channel Stability", "99.9%", "Zero dropped packets detected"]
  ],
  threats: [
    [
      "Session Key Exposure",
      "HIGH",
      "Likelihood: Low | Impact: High",
      "Absence of PFS on Child SA rekeying means that compromising long-term secrets allows retrospective decryption of recorded encrypted sessions.",
      "ACTIVE GAP"
    ],
    [
      "Metadata Profiling",
      "MEDIUM",
      "Likelihood: High | Impact: Med",
      "Statistical packet bursts and payload length clustering reveal internal application behavior (identified as continuous video streaming).",
      "OBSERVED"
    ],
    [
      "Cipher Downgrade",
      "LOW",
      "Likelihood: Low | Impact: High",
      "IKEv2 negotiation strictly enforces authenticated ECP-256 and AES-256-GCM, preventing protocol downgrade tampering.",
      "MITIGATED"
    ],
    [
      "Replay Infiltration",
      "LOW",
      "Likelihood: Low | Impact: Med",
      "Anti-replay sequence window is active across all ESP packet flows, neutralizing packet duplication and injection vectors.",
      "PROTECTED"
    ]
  ],
  scope: {
    source: "Branch Gateway 1 · Ubuntu Linux · 100.119.32.83 · StrongSwan",
    tunnel: "IPsec ESP over UDP 4500 (NAT-T) · Tunnel Mode · AES-256-GCM / ECP-256",
    receiver: "Enterprise Datacenter · Ubuntu Linux · 100.127.207.119 · StrongSwan"
  },
  trend: {
    metric: "Observed Risk Index vs Baseline",
    threshold: 40,
    points: [
      [0, 35], [5, 38], [10, 42], [15, 78], [20, 65],
      [25, 45], [30, 72], [35, 68], [40, 40], [45, 50],
      [50, 62], [56, 62]
    ],
    anomalies: [3, 6] // index of anomaly points
  },
  compliance: [
    [
      "NIST SP 800-77 Rev 1",
      "Mandates Perfect Forward Secrecy (PFS) on all IPsec phase 2 Child SAs",
      "GAP IDENTIFIED",
      "High compliance risk; non-aligned with federal cryptographic standard."
    ],
    [
      "CIS IPsec Benchmark",
      "Requires authenticated DH Group >= 14 and approved secure PRF",
      "COMPLIANT",
      "Passes key exchange cryptographic strength criteria."
    ],
    [
      "FIPS 140-3",
      "Requires approved cipher suites (AES-GCM or AES-CBC with SHA-256)",
      "COMPLIANT",
      "Cipher modules adhere to approved cryptographic algorithms."
    ],
    [
      "ISO/IEC 27001 (A.13.1)",
      "Network security management and rigorous key rotation governance",
      "PARTIAL",
      "Action required on key lifetime thresholds and PSK credential policy."
    ]
  ],
  roadmap: [
    [
      "Phase 1: Immediate",
      "0 – 48 Hours",
      "Enforce PFS on Child SA",
      "Update StrongSwan configuration to mandate ECP-256 (DH Group 19) on Child SA proposals to secure forward secrecy.",
      "Target Risk: 42 (-20 pts)"
    ],
    [
      "Phase 2: Tactical",
      "30 Days",
      "PKI Certificate Migration",
      "Deprecate static Pre-Shared Keys (PSK) and deploy X.509 enterprise machine certificates for automated mutual authentication.",
      "Compliance: +15%"
    ],
    [
      "Phase 3: Governance",
      "90 Days",
      "Continuous Posture Auditing",
      "Integrate ApexVigil daemon into SOC SIEM pipelines for continuous telemetry and automated anomaly containment.",
      "Zero Drift Assurance"
    ]
  ]
};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
const clip = (v, n) => { const s = String(v ?? ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; };
const words = (v, n) => String(v ?? "").trim().split(/\s+/).filter(Boolean).slice(0, n).join(" ");
const riskLevel = s => s >= 75 ? "CRITICAL" : s >= 50 ? "HIGH" : s >= 25 ? "MEDIUM" : "LOW";

function renderExecutiveGauge() {
  const s = Math.max(0, Math.min(100, Number(EXECUTIVE_REPORT.risk.final) || 0));
  const arc = document.getElementById("gaugeArc");
  if (arc) arc.style.strokeDasharray = `${s} 100`;
  const num = document.getElementById("gaugeNumber");
  if (num) num.textContent = s;
  const lbl = document.getElementById("gaugeRisk");
  if (lbl) lbl.textContent = `${EXECUTIVE_REPORT.risk.level || riskLevel(s)} RISK`;
}

function renderTrendChart() {
  const svg = document.getElementById("trendSvg");
  if (!svg) return;
  const W = 720, H = 220, L = 45, R = 20, T = 15, B = 30;
  const pts = Array.isArray(EXECUTIVE_REPORT.trend.points) && EXECUTIVE_REPORT.trend.points.length
    ? EXECUTIVE_REPORT.trend.points.slice(0, 50)
    : [[0, 0], [10, 0]];
  const ymax = 100;
  const xmax = Math.max(...pts.map(p => Number(p[0]) || 0), 1);
  const sx = x => L + (x / xmax) * (W - L - R);
  const sy = y => T + (H - T - B) - (y / ymax) * (H - T - B);

  let o = "";
  // Grid lines
  for (let i = 0; i <= 4; i++) {
    const y = i * 25;
    const yy = sy(y);
    o += `<line x1="${L}" y1="${yy}" x2="${W - R}" y2="${yy}" stroke="#e5e9ee" stroke-width="1"/>
          <text x="${L - 8}" y="${yy + 3}" text-anchor="end" font-size="8" fill="#8a95a3">${y}</text>`;
  }
  for (let i = 0; i <= 6; i++) {
    const x = (xmax * i) / 6;
    const xx = sx(x);
    o += `<line x1="${xx}" y1="${T}" x2="${xx}" y2="${T + H - T - B}" stroke="#edf0f3" stroke-width="1"/>
          <text x="${xx}" y="${H - 12}" text-anchor="middle" font-size="8" fill="#8a95a3">${x.toFixed(0)}s</text>`;
  }

  // Baseline threshold line
  const threshY = sy(Number(EXECUTIVE_REPORT.trend.threshold) || 40);
  o += `<line x1="${L}" y1="${threshY}" x2="${W - R}" y2="${threshY}" stroke="#c95b17" stroke-width="1.8" stroke-dasharray="4 3"/>`;

  // Plot line and area
  const line = pts.map((p, i) => (i ? "L" : "M") + sx(Number(p[0]) || 0).toFixed(1) + "," + sy(Number(p[1]) || 0).toFixed(1)).join(" ");
  const base = T + H - T - B;
  const area = line + ` L ${sx(Number(pts[pts.length - 1][0]) || 0)} ${base} L ${sx(Number(pts[0][0]) || 0)} ${base} Z`;
  o += `<path d="${area}" fill="#2d679d" opacity=".08"/>
        <path d="${line}" fill="none" stroke="#2d679d" stroke-width="2.4"/>`;

  // Points & anomaly highlights
  const anomalies = new Set(EXECUTIVE_REPORT.trend.anomalies || []);
  pts.forEach((p, idx) => {
    const cx = sx(Number(p[0]) || 0);
    const cy = sy(Number(p[1]) || 0);
    if (anomalies.has(idx)) {
      o += `<circle cx="${cx}" cy="${cy}" r="4.5" fill="#b73737" stroke="#fff" stroke-width="1.5"/>`;
    } else {
      o += `<circle cx="${cx}" cy="${cy}" r="2.5" fill="#2d679d"/>`;
    }
  });

  svg.innerHTML = o;
}

function renderExecutive() {
  // IDs & Generation
  ["reportId", "reportId2"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(EXECUTIVE_REPORT.meta.id, 32);
  });
  ["generated", "generated2"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(EXECUTIVE_REPORT.meta.generated, 32);
  });

  // Posture Banner
  const p = EXECUTIVE_REPORT.posture || {};
  const banner = document.getElementById("postureBanner");
  const badge = document.getElementById("postureBadge");
  const ans = document.getElementById("postureAns");
  const summary = document.getElementById("postureSummary");

  if (summary) summary.textContent = words(p.summary, 55);
  if (badge) badge.textContent = clip(p.status || "ATTENTION REQUIRED", 28);
  if (ans) ans.textContent = clip(p.actionRequired || "YES · HIGH", 20);

  const statusStr = String(p.status || "").toUpperCase();
  if (banner) {
    if (statusStr.includes("CRIT")) {
      banner.className = "posture-banner crit";
      if (badge) badge.className = "posture-badge crit";
      if (ans) ans.className = "decision-ans crit";
    } else if (statusStr.includes("SECURE") || statusStr.includes("SAFE")) {
      banner.className = "posture-banner safe";
      if (badge) badge.className = "posture-badge safe";
      if (ans) ans.className = "decision-ans safe";
    } else {
      banner.className = "posture-banner";
    }
  }

  // Gauge
  renderExecutiveGauge();

  // KPIs
  const kpiGrid = document.getElementById("kpiGrid");
  if (kpiGrid) {
    kpiGrid.innerHTML = (EXECUTIVE_REPORT.kpis || []).slice(0, 4).map(k => `
      <div class="kpi-card">
        <div class="kpi-label">${esc(clip(k[0], 26))}</div>
        <div class="kpi-val">${esc(clip(k[1], 16))}</div>
        <div class="kpi-sub">${esc(clip(k[2], 34))}</div>
      </div>
    `).join("");
  }

  // Threat Matrix
  const threatMatrix = document.getElementById("threatMatrix");
  if (threatMatrix) {
    threatMatrix.innerHTML = (EXECUTIVE_REPORT.threats || []).slice(0, 4).map(t => {
      const sev = String(t[1] || "MED").toLowerCase();
      return `
        <div class="threat-cell ${sev}">
          <div class="threat-title">${esc(clip(t[0], 28))}</div>
          <div class="threat-meta">
            <span>${esc(clip(t[2], 30))}</span>
          </div>
          <div class="threat-desc">${esc(clip(t[3], 130))}</div>
          <span class="threat-status-tag">${esc(clip(t[4], 16))}</span>
        </div>
      `;
    }).join("");
  }

  // Scope
  const scopeEl = document.getElementById("execScope");
  if (scopeEl) {
    const s = EXECUTIVE_REPORT.scope || {};
    scopeEl.innerHTML = `
      <div class="scope-item">
        <b>ORIGIN GATEWAY</b>
        <span>${esc(clip(s.source, 55))}</span>
      </div>
      <div class="scope-item" style="text-align:center;">
        <b>SECURED TUNNEL</b>
        <span>${esc(clip(s.tunnel, 60))}</span>
      </div>
      <div class="scope-item" style="text-align:right;">
        <b>REMOTE ENDPOINT</b>
        <span>${esc(clip(s.receiver, 55))}</span>
      </div>
    `;
  }

  // Trend Chart
  renderTrendChart();

  // Compliance Table
  const compTable = document.getElementById("complianceTable");
  if (compTable) {
    compTable.innerHTML = (EXECUTIVE_REPORT.compliance || []).slice(0, 4).map(c => {
      const st = String(c[2] || "").toUpperCase();
      let badgeCls = "badge-comp ";
      if (st.includes("COMPLIANT") && !st.includes("PARTIAL") && !st.includes("NON")) {
        badgeCls += "pass";
      } else if (st.includes("GAP") || st.includes("FAIL")) {
        badgeCls += "fail";
      } else {
        badgeCls += "gap";
      }
      return `
        <tr>
          <td>${esc(clip(c[0], 28))}</td>
          <td>${esc(clip(c[1], 55))}</td>
          <td><span class="${badgeCls}">${esc(clip(c[2], 22))}</span></td>
          <td>${esc(clip(c[3], 65))}</td>
        </tr>
      `;
    }).join("");
  }

  // Roadmap Grid
  const roadGrid = document.getElementById("roadmapGrid");
  if (roadGrid) {
    roadGrid.innerHTML = (EXECUTIVE_REPORT.roadmap || []).slice(0, 3).map(r => `
      <div class="road-card">
        <div class="road-phase">${esc(clip(r[0], 22))}</div>
        <div class="road-time">${esc(clip(r[1], 18))}</div>
        <div class="road-action">${esc(clip(r[2], 26))}</div>
        <div class="road-desc">${esc(clip(r[3], 120))}</div>
        <div class="road-kpi">${esc(clip(r[4], 30))}</div>
      </div>
    `).join("");
  }
}

document.addEventListener("DOMContentLoaded", renderExecutive);
