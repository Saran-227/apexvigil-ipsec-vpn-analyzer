/* APEX VIGIL SECURITY ASSESSMENT REPORT DATA CONTRACT
   Ollama returns values only. It never controls HTML/CSS/presentation.
   Hard limits: summary 55 words, weightage rows 5, deductions 4,
   defects 5, remediation steps 4, projection summary 60 words. */

const ASSESSMENT_REPORT = {
  meta: {
    id: "AV-2026-AUDIT-001",
    generated: "15 September 2026",
    capture: "sih26-asim-golden.pcap",
    analysisPeriod: "15 Sep 2026 | 01:21:06 – 01:22:03"
  },
  summary: "The IPsec deployment scored 77.0 out of 100 (Grade B+), indicating moderately strong transport confidentiality via AES-256-GCM, but notable architectural gaps in forward secrecy and authentication. A total of 23 penalty points were deducted across four key security parameters. Following the targeted remediation playbook will raise the posture score to 96/100 (Grade A+).",
  scores: {
    composite: 77,
    grade: "GRADE B+ · MODERATE RISK",
    cryptoBaseline: 70,
    anomalyIntegrity: 84,
    totalDeductions: "-23 pts"
  },
  weightage: [
    [
      "Cryptographic Suite & AEAD",
      "30%",
      30,
      26,
      "AES-256-GCM enforced; minor PRF truncation note"
    ],
    [
      "Key Management & PFS",
      "25%",
      25,
      14,
      "PFS disabled on Child SA; extended rekey lifetime"
    ],
    [
      "Authentication & Identity",
      "20%",
      20,
      15,
      "Static PSK observed; lacks X.509 certificate hierarchy"
    ],
    [
      "Operational Replay Protection",
      "15%",
      15,
      15,
      "Anti-replay window active (32 pkts); zero replay gaps"
    ],
    [
      "Metadata & Anomaly Resilience",
      "10%",
      10,
      7,
      "Packet length clustering allows video profiling"
    ]
  ],
  deductions: [
    [
      "PFS Disabled (Child SA)",
      "-11 pts",
      "crit",
      "Single Key Compromise Decrypts Past Data",
      "Absence of Diffie-Hellman rekeying for Child SAs violates forward secrecy. If the initial key is exposed, all past recorded traffic can be retrospectively deciphered.",
      "Risk: Critical (NIST 800-77 Non-compliant)"
    ],
    [
      "Pre-Shared Key (PSK)",
      "-5 pts",
      "high",
      "Vulnerable to Offline Cracking",
      "Symmetric shared secret authentication lacks identity non-repudiation and makes both peers vulnerable if a weak passphrase is brute-forced.",
      "Risk: Medium-High (RFC 8221 Violation)"
    ],
    [
      "Extended SA Lifetime",
      "-4 pts",
      "med",
      "Prolonged Cryptanalytic Attack Surface",
      "Observed SA lifetime exceeds the recommended 3600-second / 1GB rotation interval, widening the window for cryptoanalysis.",
      "Risk: Medium (SA Exposure Window)"
    ],
    [
      "Traffic Burst & Padding Gap",
      "-3 pts",
      "med",
      "Side-Channel Metadata Leakage",
      "Insufficient ESP padding randomization allows packet size heuristics to fingerprint the encapsulated video traffic stream.",
      "Risk: Low-Medium (Inference Attack)"
    ]
  ],
  chartData: {
    domains: ["Crypto Suite", "Key Mgmt & PFS", "Authentication", "Replay Prot.", "Metadata Resil."],
    targets: [30, 25, 20, 15, 10],
    scored: [26, 14, 15, 15, 7]
  },
  defects: [
    [
      "SEC-01",
      "Forward Secrecy (PFS)",
      "Disabled",
      "-11 pts",
      "Lack of DH group proposal in Child SA allows past session decryption upon master key compromise."
    ],
    [
      "SEC-02",
      "Authentication Method",
      "PSK (Shared Secret)",
      "-5 pts",
      "Pre-shared keying lacks automated credential rotation and hardware security token binding."
    ],
    [
      "SEC-03",
      "SA Rekey Threshold",
      "Extended (>8 hrs)",
      "-4 pts",
      "Exceeds 3600s threshold, exposing millions of packets under an identical cryptographic keystream."
    ],
    [
      "SEC-04",
      "Side-Channel Padding",
      "Standard ESP Pad",
      "-3 pts",
      "Uniform padding allows packet length analysis to accurately identify internal video streaming."
    ],
    [
      "SEC-05",
      "Replay Window Size",
      "32 Packets",
      "0 pts",
      "Standard 32-packet anti-replay sliding window active; fully compliant with RFC 4303."
    ]
  ],
  severities: {
    critical: 1,
    high: 1,
    medium: 2,
    low: 1
  },
  remediation: [
    [
      "1. Mandate ECP-256 (DH Group 19) in Child SA",
      "+11 pts",
      "Append 'aes256gcm16-ecp256!' to the esp proposal in /etc/swanctl/conf.d/ipsec.conf to force ephemeral DH exchange upon every rekey."
    ],
    [
      "2. Transition from PSK to X.509 PKI Certificates",
      "+5 pts",
      "Generate Elliptic Curve (ECDSA-256) machine certificates and reconfigure StrongSwan with 'authby = pubkey' for automated non-repudiation."
    ],
    [
      "3. Restrict SA Rekey Lifetime & Byte Ceiling",
      "+4 pts",
      "Set 'lifetime = 3600s' and 'lifebytes = 1000M' under connection definition to enforce deterministic session rekeying."
    ],
    [
      "4. Enable Random ESP Length Obfuscation",
      "+3 pts",
      "Activate IPsec traffic obfuscation padding to disrupt packet-size clustering models and neutralize traffic profiling."
    ]
  ],
  llm: {
    priorityTitle: "Priority Remediation Directive",
    priorityText: "Enable Perfect Forward Secrecy immediately in the StrongSwan Child SA definition. While the in-transit AES-GCM encryption is strong, lack of PFS represents the single greatest vulnerability to retroactive decryption.",
    actionTitle: "Recommended Action Plan",
    actionText: "Apply DH Group 19 to Child SA proposals, restart StrongSwan via 'swanctl --load-all', and verify the active connection state with 'swanctl --list-sas'."
  },
  projection: {
    current: "77 / 100",
    gain: "+19 pts",
    final: "96 / 100",
    grade: "GRADE A+ · FULLY HARDENED",
    summary: "Executing the top two priority directives (enabling PFS Diffie-Hellman Group 19 and migrating from PSK to X.509 enterprise certificates) will immediately eliminate 16 penalty points. This transforms the IPsec deployment from a conditionally acceptable posture into an enterprise-grade hardened state fully compliant with NIST SP 800-77 Rev 1."
  }
};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
const clip = (v, n) => { const s = String(v ?? ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; };
const words = (v, n) => String(v ?? "").trim().split(/\s+/).filter(Boolean).slice(0, n).join(" ");

function renderAuditGauge() {
  const s = Math.max(0, Math.min(100, Number(ASSESSMENT_REPORT.scores.composite) || 0));
  const arc = document.getElementById("auditGaugeArc");
  if (arc) arc.style.strokeDasharray = `${s} 100`;
  const num = document.getElementById("auditGaugeNumber");
  if (num) num.textContent = s;
  const grade = document.getElementById("auditGaugeGrade");
  if (grade) grade.textContent = clip(ASSESSMENT_REPORT.scores.grade || "GRADE B+ · MODERATE RISK", 32);
}

function renderDomainChart() {
  const svg = document.getElementById("domainSvg");
  if (!svg) return;
  const W = 720, H = 210, L = 50, R = 25, T = 15, B = 35;
  const cd = ASSESSMENT_REPORT.chartData || {};
  const labels = (cd.domains || []).slice(0, 5);
  const targets = (cd.targets || []).slice(0, 5);
  const scored = (cd.scored || []).slice(0, 5);
  const N = labels.length || 5;

  let o = "";
  // Grid lines
  for (let i = 0; i <= 3; i++) {
    const yVal = i * 10;
    const yNorm = yVal / 30; // 30 is max target
    const yy = T + (H - T - B) - yNorm * (H - T - B);
    o += `<line x1="${L}" y1="${yy}" x2="${W - R}" y2="${yy}" stroke="#e5e9ee" stroke-width="1"/>
          <text x="${L - 8}" y="${yy + 3}" text-anchor="end" font-size="8" fill="#8a95a3">${yVal} pts</text>`;
  }

  const groupWidth = (W - L - R) / N;
  const barWidth = 18;

  for (let i = 0; i < N; i++) {
    const gx = L + i * groupWidth + groupWidth / 2;
    const tVal = Number(targets[i]) || 0;
    const sVal = Number(scored[i]) || 0;

    const tNorm = Math.min(1, tVal / 30);
    const sNorm = Math.min(1, sVal / 30);

    const tH = tNorm * (H - T - B);
    const sH = sNorm * (H - T - B);

    const tY = T + (H - T - B) - tH;
    const sY = T + (H - T - B) - sH;

    // Target Bar (slate/grey)
    o += `<rect x="${gx - barWidth - 2}" y="${tY}" width="${barWidth}" height="${tH}" fill="#cbd6e2" rx="2"/>`;
    // Score Bar (navy/blue)
    const barFill = sVal < tVal * 0.7 ? "#c95b17" : "#2d679d";
    o += `<rect x="${gx + 2}" y="${sY}" width="${barWidth}" height="${sH}" fill="${barFill}" rx="2"/>`;

    // Bar top numbers
    o += `<text x="${gx - barWidth / 2 - 2}" y="${tY - 3}" text-anchor="middle" font-size="7" fill="#728394">${tVal}</text>`;
    o += `<text x="${gx + barWidth / 2 + 2}" y="${sY - 3}" text-anchor="middle" font-size="7" font-weight="bold" fill="${barFill}">${sVal}</text>`;

    // X-axis Label
    o += `<text x="${gx}" y="${H - 12}" text-anchor="middle" font-size="7.5" fill="#445568" font-weight="600">${esc(clip(labels[i], 18))}</text>`;
  }

  svg.innerHTML = o;
}

function renderAssessment() {
  // IDs & Generation
  ["reportId", "reportId2", "reportId3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(ASSESSMENT_REPORT.meta.id, 32);
  });
  ["generated", "generated2", "generated3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(ASSESSMENT_REPORT.meta.generated, 32);
  });

  // Summary
  const sumEl = document.getElementById("auditSummary");
  if (sumEl) sumEl.textContent = words(ASSESSMENT_REPORT.summary, 55);

  // Scores
  renderAuditGauge();
  const sc = ASSESSMENT_REPORT.scores || {};
  const cEl = document.getElementById("cryptoScore");
  if (cEl) cEl.textContent = sc.cryptoBaseline ?? 70;
  const aEl = document.getElementById("anomalyScore");
  if (aEl) aEl.textContent = sc.anomalyIntegrity ?? 84;
  const penEl = document.getElementById("totalPenalty");
  if (penEl) penEl.innerHTML = `${esc(clip(sc.totalDeductions ?? "-23 pts", 12))}`;

  // Weightage Table
  const wTable = document.getElementById("weightageTable");
  if (wTable) {
    wTable.innerHTML = (ASSESSMENT_REPORT.weightage || []).slice(0, 5).map(r => {
      const target = Number(r[2]) || 1;
      const scored = Number(r[3]) || 0;
      const pct = Math.round((scored / target) * 100);
      let barCls = "mini-bar";
      if (pct < 65) barCls += " crit";
      else if (pct < 85) barCls += " warn";

      return `
        <tr>
          <td>${esc(clip(r[0], 28))}</td>
          <td><b>${esc(clip(r[1], 10))}</b></td>
          <td>${target} pts</td>
          <td><b>${scored} pts</b></td>
          <td>
            <div class="weight-bar-cell">
              <div class="${barCls}"><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></div>
              <span style="font-family:'Courier New',monospace;font-size:6px;font-weight:bold;min-width:20px;">${pct}%</span>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  // Deductions Grid
  const dGrid = document.getElementById("deductionsGrid");
  if (dGrid) {
    dGrid.innerHTML = (ASSESSMENT_REPORT.deductions || []).slice(0, 4).map(d => {
      const cls = String(d[2] || "med").toLowerCase();
      return `
        <div class="deduction-card ${cls}">
          <div class="deduction-header">
            <span class="deduction-param">${esc(clip(d[0], 24))}</span>
            <span class="deduction-pts">${esc(clip(d[1], 10))}</span>
          </div>
          <div class="deduction-why-lbl">ROOT CAUSE / GAP</div>
          <div class="deduction-why-text">${esc(clip(d[4], 120))}</div>
          <div class="deduction-impact">${esc(clip(d[5], 34))}</div>
        </div>
      `;
    }).join("");
  }

  // Domain Chart
  renderDomainChart();

  // Defect Table
  const defTable = document.getElementById("defectTable");
  if (defTable) {
    defTable.innerHTML = (ASSESSMENT_REPORT.defects || []).slice(0, 5).map(df => {
      const pen = String(df[3] || "");
      let pCls = "badge-penalty";
      if (pen.includes("0") || pen === "") pCls += " info";
      else if (pen.includes("11") || pen.includes("crit")) pCls += "";
      else pCls += " warn";

      return `
        <tr>
          <td style="font-family:'Courier New',monospace;font-weight:bold;">${esc(clip(df[0], 12))}</td>
          <td>${esc(clip(df[1], 24))}</td>
          <td>${esc(clip(df[2], 22))}</td>
          <td><span class="${pCls}">${esc(clip(df[3], 12))}</span></td>
          <td>${esc(clip(df[4], 125))}</td>
        </tr>
      `;
    }).join("");
  }

  // Severity Summary
  const sevEl = document.getElementById("severitySummary");
  if (sevEl) {
    const s = ASSESSMENT_REPORT.severities || {};
    sevEl.innerHTML = `
      <div class="score-stat-card" style="border-top:2px solid var(--red);text-align:center;">
        <div class="s-lbl">CRITICAL</div>
        <div class="s-num" style="color:var(--red);">${s.critical ?? 0}</div>
        <div class="s-sub">Immediate Action</div>
      </div>
      <div class="score-stat-card" style="border-top:2px solid var(--orange);text-align:center;">
        <div class="s-lbl">HIGH</div>
        <div class="s-num" style="color:var(--orange);">${s.high ?? 0}</div>
        <div class="s-sub">Action in 48h</div>
      </div>
      <div class="score-stat-card" style="border-top:2px solid var(--yellow);text-align:center;">
        <div class="s-lbl">MEDIUM</div>
        <div class="s-num" style="color:#b27d11;">${s.medium ?? 0}</div>
        <div class="s-sub">30-day target</div>
      </div>
      <div class="score-stat-card" style="border-top:2px solid var(--green);text-align:center;">
        <div class="s-lbl">LOW / INFORMATIONAL</div>
        <div class="s-num" style="color:var(--green);">${s.low ?? 0}</div>
        <div class="s-sub">Compliant state</div>
      </div>
    `;
  }

  // Remediation Steps
  const remEl = document.getElementById("remedSteps");
  if (remEl) {
    remEl.innerHTML = (ASSESSMENT_REPORT.remediation || []).slice(0, 4).map(r => `
      <div class="remed-step">
        <div class="step-title">
          <span>${esc(clip(r[0], 36))}</span>
          <span class="step-gain">${esc(clip(r[1], 10))}</span>
        </div>
        <div class="step-desc">${esc(clip(r[2], 125))}</div>
      </div>
    `).join("");
  }

  // AI LLM Box
  const l = ASSESSMENT_REPORT.llm || {};
  const aiPT = document.getElementById("aiPriorityTitle");
  if (aiPT) aiPT.textContent = clip(l.priorityTitle || "Priority Remediation Directive", 40);
  const aiPTxt = document.getElementById("aiPriorityText");
  if (aiPTxt) aiPTxt.textContent = clip(l.priorityText || "", 240);
  const aiAT = document.getElementById("aiActionTitle");
  if (aiAT) aiAT.textContent = clip(l.actionTitle || "Recommended Action Plan", 40);
  const aiATxt = document.getElementById("aiActionText");
  if (aiATxt) aiATxt.textContent = clip(l.actionText || "", 240);

  // Projections
  const pr = ASSESSMENT_REPORT.projection || {};
  const pCur = document.getElementById("projCurrent");
  if (pCur) pCur.textContent = clip(pr.current || "77 / 100", 14);
  const pGain = document.getElementById("projGain");
  if (pGain) pGain.textContent = clip(pr.gain || "+19 pts", 12);
  const pFin = document.getElementById("projFinal");
  if (pFin) pFin.textContent = clip(pr.final || "96 / 100", 14);
  const pGrd = document.getElementById("projGrade");
  if (pGrd) pGrd.textContent = clip(pr.grade || "GRADE A+", 26);
  const pSum = document.getElementById("projSummary");
  if (pSum) pSum.textContent = words(pr.summary, 60);
}

document.addEventListener("DOMContentLoaded", renderAssessment);
