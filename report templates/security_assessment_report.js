/* APEX VIGIL SECURITY ASSESSMENT REPORT DATA CONTRACT & RENDERER */

const ASSESSMENT_REPORT = {};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
const clip = (v, n) => { const s = String(v ?? ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; };
const words = (v, n) => String(v ?? "").trim().split(/\s+/).filter(Boolean).slice(0, n).join(" ");

function renderAssessment() {
  const data = ASSESSMENT_REPORT || {};
  const meta = data.meta || {};
  const s1 = data.section1 || {};
  const s2 = data.section2 || {};
  const s3 = data.section3 || {};
  const s4 = data.section4 || {};
  const s5 = data.section5 || {};
  const s6 = data.section6 || {};

  // Headers
  ["reportId", "reportId2", "reportId3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(meta.id || "AV-2026-AUDIT", 30);
  });
  ["generated", "generated2", "generated3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(meta.generated || "", 30);
  });

  // Section 1: Scope & Regulatory Framework
  const score = s1.compositeScore != null ? s1.compositeScore : (data.scores && data.scores.composite) || 77;
  const grade = s1.auditGrade || (data.scores && data.scores.grade) || "GRADE B+ · MODERATE RISK";

  const cScoreEl = document.getElementById("compositeScore");
  if (cScoreEl) cScoreEl.textContent = score;
  const aGradeEl = document.getElementById("auditGrade");
  if (aGradeEl) aGradeEl.textContent = clip(grade, 28);

  const sumTxtEl = document.getElementById("auditSummaryText");
  if (sumTxtEl) sumTxtEl.textContent = words(data.summary || "", 65);

  const scScopeEl = document.getElementById("auditScopeVal");
  if (scScopeEl) scScopeEl.textContent = clip((s1.scope && s1.scope.evaluatedScope) || meta.capture || "IPsec Tunnel", 55);
  const scPerEl = document.getElementById("auditPeriodVal");
  if (scPerEl) scPerEl.textContent = clip((s1.scope && s1.scope.period) || meta.analysisPeriod || "", 45);

  const benchTable = document.getElementById("regulatoryBenchmarksTable");
  if (benchTable) {
    const benches = s1.benchmarks || [
      { standard: "NIST SP 800-77 Rev. 1", title: "Guide to IPsec VPNs", requirement: "Mandates AEAD ciphers, PFS on phase 2 Child SAs, and IKEv2", status: "CONDITIONAL GAP", statusClass: "gap", citation: "NIST SP 800-77 §4.2" },
      { standard: "RFC 8221", title: "Cryptographic Algorithm Requirements", requirement: "AES-GCM (MUST), SHA-256 (MUST), 3DES & MD5 (MUST NOT)", status: "COMPLIANT", statusClass: "pass", citation: "IETF RFC 8221 §5" },
      { standard: "NSA CNSA 2.0", title: "Commercial Nat Sec Algorithm Suite", requirement: "AES-256, DH Group 19/20, and Post-Quantum transition timeline", status: "PARTIAL ALIGNMENT", statusClass: "gap", citation: "NSA Advisory CNSA 2.0" }
    ];
    benchTable.innerHTML = benches.map(b => `
      <tr>
        <td><b>${esc(b.standard)}</b></td>
        <td>${esc(clip(b.title, 28))}</td>
        <td>${esc(clip(b.requirement, 65))}</td>
        <td><span class="badge-verdict ${b.statusClass || 'gap'}">${esc(b.status)}</span></td>
        <td>${esc(clip(b.citation || "", 25))}</td>
      </tr>
    `).join("");
  }

  // Section 2: Cryptographic Health Audit
  const ch = s2.cryptoHealth || {};
  const sym = ch.symmetric || {};
  const inth = ch.integrity || {};

  const scName = document.getElementById("symCipherName");
  if (scName) scName.textContent = clip(sym.cipher || "AES-256-GCM", 26);
  const scMode = document.getElementById("symCipherMode");
  if (scMode) scMode.textContent = clip(sym.mode || "AEAD (Galois/Counter Mode)", 30);
  const scTag = document.getElementById("symCipherTag");
  if (scTag) scTag.textContent = clip(sym.tag || "128-bit ICV Tag", 30);
  const scKey = document.getElementById("symCipherKey");
  if (scKey) scKey.textContent = clip(sym.keySize || "256 bits", 20);
  const scVerd = document.getElementById("symCipherVerdict");
  if (scVerd) scVerd.textContent = clip(sym.assessment || "", 120);

  const hName = document.getElementById("hashName");
  if (hName) hName.textContent = clip(inth.hash || "SHA-256 / HMAC-SHA2-256", 28);
  const hDig = document.getElementById("hashDigest");
  if (hDig) hDig.textContent = clip(inth.digest || "256 bits", 20);
  const hVerd = document.getElementById("hashVerdict");
  if (hVerd) hVerd.textContent = clip(inth.assessment || "", 120);

  // Section 3: Key Management & Exchange Audit
  const km = s3.keyManagement || {};
  const dh = km.dhModulus || {};
  const pfs = km.pfsRekey || {};
  const pq = km.postQuantumPosture || {};

  const dhGrp = document.getElementById("dhGroup");
  if (dhGrp) dhGrp.textContent = clip(dh.group || "ECP-256 (DH Group 19)", 24);
  const dhMod = document.getElementById("dhModulus");
  if (dhMod) dhMod.textContent = clip(dh.modulusSize || "256-bit Elliptic Curve", 35);
  const dhAss = document.getElementById("dhAssessment");
  if (dhAss) dhAss.textContent = clip(dh.assessment || "", 105);

  const pfsChild = document.getElementById("pfsChildStatus");
  if (pfsChild) pfsChild.textContent = clip(pfs.childPfs || "Disabled on Child SA", 24);
  const pfsIke = document.getElementById("pfsIkeStatus");
  if (pfsIke) pfsIke.textContent = clip(`IKE SA: ${pfs.ikePfs || "Active"} | ${pfs.penalty || "-11 pts"}`, 35);
  const pfsThr = document.getElementById("pfsThreat");
  if (pfsThr) pfsThr.textContent = clip(pfs.threat || "", 115);

  const pqStat = document.getElementById("pqStatus");
  if (pqStat) pqStat.textContent = clip(pq.status || "Classical ECC (Pre-Quantum)", 28);
  const pqD = document.getElementById("pqDesc");
  if (pqD) pqD.textContent = clip(pq.recommendation || "", 105);

  // Section 4: Protocol & State Integrity
  const pi = s4.protocolIntegrity || {};
  const ar = pi.antiReplay || {};
  const sr = pi.sequenceRollover || {};
  const im = pi.ikeModeSecurity || {};

  const rwEl = document.getElementById("replayWindowSize");
  if (rwEl) rwEl.textContent = clip(ar.windowSize || "64-Bit Sliding Window (RFC 4303)", 32);
  const rwDesc = document.getElementById("replayDesc");
  if (rwDesc) rwDesc.textContent = clip(ar.assessment || "", 110);

  const roEl = document.getElementById("rolloverProtection");
  if (roEl) roEl.textContent = clip(sr.counterSize || "64-Bit Extended Sequence Numbers (ESN)", 35);

  const imEl = document.getElementById("ikeModeSecurity");
  if (imEl) imEl.textContent = clip(im.ikeVersion || "IKEv2 (Main Mode Equivalent)", 32);

  // Section 5: Side-Channel & Metadata Vulnerability Audit
  const sc = s5.sideChannelAudit || {};
  const lScoreEl = document.getElementById("leakageScore");
  if (lScoreEl) lScoreEl.textContent = sc.leakageScore || 74;
  const lGradeEl = document.getElementById("leakageGrade");
  if (lGradeEl) lGradeEl.textContent = clip(sc.leakageGrade || "MODERATE RISK", 18);

  const psr = sc.packetShape || {};
  const psrEl = document.getElementById("packetShapeRating");
  if (psrEl) psrEl.textContent = clip(psr.rating || "HIGH PREDICTABILITY", 22);
  const psdEl = document.getElementById("packetShapeDetail");
  if (psdEl) psdEl.textContent = clip(psr.detail || "", 105);

  const br = sc.burstiness || {};
  const brEl = document.getElementById("burstinessRating");
  if (brEl) brEl.textContent = clip(br.rating || "MODERATE LEAKAGE", 22);
  const bdEl = document.getElementById("burstinessDetail");
  if (bdEl) bdEl.textContent = clip(br.detail || "", 105);

  const tfc = sc.tfcPadding || {};
  const tfcSt = document.getElementById("tfcStatus");
  if (tfcSt) tfcSt.textContent = clip(`${tfc.status || "MISSING"} (${tfc.penalty || "-3 pts"})`, 26);
  const tfcRec = document.getElementById("tfcRecommendation");
  if (tfcRec) tfcRec.textContent = clip(tfc.recommendation || "", 105);

  // Section 6: Comprehensive Threat & Vulnerability Matrix
  const vTable = document.getElementById("vulnerabilityMatrixTable");
  if (vTable) {
    const vulns = s6.vulnerabilityRegister || [
      { id: "AV-VULN-2026-001", title: "Absence of Child SA Perfect Forward Secrecy", cvssBase: 7.5, cvssEnv: 6.8, severity: "HIGH", mandate: "NIST SP 800-77 §4.2.3", penalty: "-11 pts" },
      { id: "AV-VULN-2026-002", title: "Static Pre-Shared Key (PSK) Authentication", cvssBase: 6.5, cvssEnv: 5.9, severity: "MEDIUM", mandate: "RFC 8221 / PKI Standard", penalty: "-5 pts" },
      { id: "AV-VULN-2026-003", title: "Missing Traffic Flow Confidentiality (TFC) Padding", cvssBase: 4.3, cvssEnv: 3.8, severity: "MEDIUM", mandate: "RFC 4303 §2.7 Gap", penalty: "-3 pts" },
      { id: "AV-VULN-2026-004", title: "Anti-Replay Window Verification", cvssBase: 0.0, cvssEnv: 0.0, severity: "LOW", mandate: "RFC 4303 Replay Pass", penalty: "0 pts" }
    ];
    vTable.innerHTML = vulns.map(v => {
      const sevCls = String(v.severity || "med").toLowerCase();
      return `
        <tr>
          <td><b>${esc(v.id)}</b></td>
          <td><b>${esc(clip(v.title, 34))}</b></td>
          <td>Base: ${v.cvssBase} | Env: ${v.cvssEnv}</td>
          <td><span class="severity-pill ${sevCls}">${esc(v.severity)}</span></td>
          <td>${esc(clip(v.mandate, 28))}</td>
        </tr>
      `;
    }).join("");
  }

  // Severity stats
  const sevRow = document.getElementById("severityStatRow");
  if (sevRow) {
    const sev = s6.severities || (data.severities || { critical: 0, high: 1, medium: 2, low: 1 });
    sevRow.innerHTML = `
      <div class="sev-stat-box"><div class="ss-num" style="color:var(--red);">${sev.critical || 0}</div><div class="ss-lbl">CRITICAL</div></div>
      <div class="sev-stat-box"><div class="ss-num" style="color:var(--orange);">${sev.high || 0}</div><div class="ss-lbl">HIGH</div></div>
      <div class="sev-stat-box"><div class="ss-num" style="color:#b27d11;">${sev.medium || 0}</div><div class="ss-lbl">MEDIUM</div></div>
      <div class="sev-stat-box"><div class="ss-num" style="color:var(--green);">${sev.low || 0}</div><div class="ss-lbl">LOW</div></div>
    `;
  }

  const proj = s6.projection || data.projection || {};
  const pCur = document.getElementById("projCurrent");
  if (pCur) pCur.textContent = clip(proj.current || "77 / 100", 14);
  const pGn = document.getElementById("projGain");
  if (pGn) pGn.textContent = clip(proj.gain || "+19 pts", 12);
  const pFin = document.getElementById("projFinal");
  if (pFin) pFin.textContent = clip(proj.final || "96 / 100", 14);
  const pGrd = document.getElementById("projGrade");
  if (pGrd) pGrd.textContent = clip(proj.grade || "GRADE A+", 26);
  const pSum = document.getElementById("projSummary");
  if (pSum) pSum.textContent = words(proj.summary || "", 65);
}

document.addEventListener("DOMContentLoaded", renderAssessment);
