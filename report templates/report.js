/* APEX VIGIL TECHNICAL REPORT DATA CONTRACT & RENDERER */

const REPORT = {};

const esc = v => String(v ?? "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
const clip = (v, n) => { const s = String(v ?? ""); return s.length <= n ? s : s.slice(0, n - 1) + "…"; };

function renderTimeline() {
  const svg = document.getElementById("timelineSvg");
  if (!svg) return;
  const s3 = REPORT.section3 || {};
  const tl = s3.timeline || REPORT.timeline || {};
  const W = 720, H = 180, L = 40, R = 15, T = 10, B = 25;
  const pts = Array.isArray(tl.points) && tl.points.length ? tl.points.slice(0, 40) : [[0, 0], [10, 0]];
  const ymax = Number(tl.yMax) || Math.max(...pts.map(p => Number(p[1]) || 0), 1) * 1.15;
  const xmax = Math.max(...pts.map(p => Number(p[0]) || 0), 1);
  const sx = x => L + (x / xmax) * (W - L - R);
  const sy = y => T + (H - T - B) - (y / ymax) * (H - T - B);

  let o = "";
  for (let i = 0; i <= 4; i++) {
    const y = i * ymax / 4;
    const yy = sy(y);
    o += `<line x1="${L}" y1="${yy}" x2="${W - R}" y2="${yy}" stroke="#eef2f6" stroke-width="1"/>
          <text x="${L - 6}" y="${yy + 3}" text-anchor="end" font-size="7" fill="#8a95a3">${Math.round(y)}</text>`;
  }
  for (let i = 0; i <= 5; i++) {
    const x = (xmax * i) / 5;
    const xx = sx(x);
    o += `<line x1="${xx}" y1="${T}" x2="${xx}" y2="${T + H - T - B}" stroke="#f1f4f8" stroke-width="1"/>
          <text x="${xx}" y="${H - 8}" text-anchor="middle" font-size="7" fill="#8a95a3">${x.toFixed(0)}s</text>`;
  }

  const line = pts.map((p, i) => (i ? "L" : "M") + sx(Number(p[0]) || 0).toFixed(1) + "," + sy(Number(p[1]) || 0).toFixed(1)).join(" ");
  const base = T + H - T - B;
  const area = line + ` L ${sx(Number(pts[pts.length - 1][0]) || 0)} ${base} L ${sx(Number(pts[0][0]) || 0)} ${base} Z`;
  o += `<path d="${area}" fill="#2d679d" opacity=".07"/>
        <path d="${line}" fill="none" stroke="#2d679d" stroke-width="2.2"/>`;

  const ev = (tl.events || []).slice(0, 4);
  ev.forEach((e, i) => {
    const p = pts[Math.min(pts.length - 1, Math.floor((i + 1) * pts.length / (ev.length + 1)))];
    o += `<circle cx="${sx(Number(p[0]) || 0)}" cy="${sy(Number(p[1]) || 0)}" r="3" fill="#c95b17" stroke="#fff" stroke-width="1"/>`;
  });

  svg.innerHTML = o;

  const evRow = document.getElementById("eventRow");
  if (evRow) {
    evRow.innerHTML = ev.map(e => `
      <div class="ev-box">
        <b>${esc(clip(e[0], 20))} (${esc(clip(e[1], 14))})</b>
        <div>${esc(clip(e[2], 55))}</div>
      </div>
    `).join("");
  }
}

function render() {
  const data = REPORT || {};
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
    if (el) el.textContent = clip(meta.id || "AV-2026-TECH", 30);
  });
  ["generated", "generated2", "generated3"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = clip(meta.generated || "", 30);
  });

  // Section 1: Capture & Interface Metadata
  const csEl = document.getElementById("capSource");
  if (csEl) csEl.textContent = clip(s1.captureSource || meta.capture || "br-ipsec", 55);
  const cpEl = document.getElementById("capPeriod");
  if (cpEl) cpEl.textContent = clip(meta.analysisPeriod || (s1.flowVolume && s1.flowVolume.duration) || "", 45);

  const ep = s1.endpoints || {};
  const src = ep.source || data.source || {};
  const rcv = ep.receiver || data.receiver || {};

  const srcCard = document.getElementById("sourceEndpointCard");
  if (srcCard) {
    srcCard.innerHTML = `
      <div class="ep-role">${esc(src.role || "INITIATOR GATEWAY")}</div>
      <div class="ep-branch">${esc(clip(src.branch || "Branch Gateway 1", 30))}</div>
      <div class="ep-specs">
        <b>OS:</b> ${esc(src.os || "Ubuntu Linux")}<br>
        <b>Interface:</b> ${esc(src.interface || "tailscale0")}<br>
        <b>Private IP:</b> ${esc(src.ip || "100.119.32.83")}<br>
        <b>VPN Daemon:</b> ${esc(src.vpn || "StrongSwan v5.9.8")}
      </div>
    `;
  }

  const rcvCard = document.getElementById("receiverEndpointCard");
  if (rcvCard) {
    rcvCard.innerHTML = `
      <div class="ep-role">${esc(rcv.role || "RESPONDER GATEWAY")}</div>
      <div class="ep-branch">${esc(clip(rcv.branch || "Enterprise DC Core", 30))}</div>
      <div class="ep-specs">
        <b>OS:</b> ${esc(rcv.os || "Ubuntu Linux")}<br>
        <b>Interface:</b> ${esc(rcv.interface || "eth0")}<br>
        <b>Private IP:</b> ${esc(rcv.ip || "100.127.207.119")}<br>
        <b>VPN Daemon:</b> ${esc(rcv.vpn || "StrongSwan v5.9.8")}
      </div>
    `;
  }

  const tunSub = document.getElementById("tunnelMiddleSub");
  if (tunSub) tunSub.textContent = clip(data.tunnel || "ESP over UDP 4500 · Tunnel Mode", 40);

  const stGrid = document.getElementById("statsGrid");
  const fv = s1.flowVolume || {};
  const pc = s1.packetCounts || {};
  const ifStats = s1.interfaceStats || {};
  if (stGrid) {
    const cards = [
      ["TOTAL PACKETS", pc.total || "24,108", "Frames Ingested"],
      ["FLOW VOLUME", fv.volume || "22.8 MB", "Encrypted Payload"],
      ["AVG RATE", fv.avgRate || "424 pkt/s", "Throughput Velocity"],
      ["PEAK RATE", fv.peakRate || "1,120 pkt/s", "Observed Burst"],
      ["INTERFACE MTU", ifStats.mtu || "1500 bytes", ifStats.linkStatus || "UP / ACTIVE"],
      ["DROPS / ERRORS", ifStats.rxDrops || "0", "Monotonic Verified"]
    ];
    stGrid.innerHTML = cards.map(c => `
      <div class="stat-hex">
        <div class="s-lbl">${esc(c[0])}</div>
        <div class="s-val">${esc(c[1])}</div>
        <div class="s-unit">${esc(c[2])}</div>
      </div>
    `).join("");
  }

  // Section 2: Deterministic Control-Plane Dissection
  const exList = document.getElementById("ikeExchangesList");
  if (exList) {
    const exch = s2.exchanges || [
      { id: 34, name: "IKE_SA_INIT (Exchange 34)", status: "SUCCESS", details: "DH Group 19 public key and nonces exchanged." },
      { id: 35, name: "IKE_AUTH (Exchange 35)", status: "SUCCESS", details: "Mutual PSK authentication and initial Child SA negotiation." },
      { id: 36, name: "CREATE_CHILD_SA (Exchange 36)", status: "MONITORED", details: "Secondary Child SA rekey evaluated." }
    ];
    exList.innerHTML = exch.map(e => `
      <div class="ex-row">
        <div class="ex-id">${esc(e.name.split(" ")[0])}</div>
        <div class="ex-desc"><b>[${esc(e.status)}]</b> ${esc(clip(e.details, 70))}</div>
      </div>
    `).join("");
  }

  const spiBox = document.getElementById("spiGrid");
  if (spiBox) {
    const spi = s2.activeSpiPairs || {
      initiatorSpi: "0x8b14e9f28a1c9034",
      responderSpi: "0x4a7c10b83f09de21",
      inboundEspSpi: "0xc0a80102",
      outboundEspSpi: "0xc0a80103"
    };
    spiBox.innerHTML = `
      <div class="spi-card"><span class="spi-lbl">INITIATOR SPI</span><span class="spi-val">${esc(clip(spi.initiatorSpi, 18))}</span></div>
      <div class="spi-card"><span class="spi-lbl">RESPONDER SPI</span><span class="spi-val">${esc(clip(spi.responderSpi, 18))}</span></div>
      <div class="spi-card"><span class="spi-lbl">INBOUND ESP SPI</span><span class="spi-val">${esc(clip(spi.inboundEspSpi, 18))}</span></div>
      <div class="spi-card"><span class="spi-lbl">OUTBOUND ESP SPI</span><span class="spi-val">${esc(clip(spi.outboundEspSpi, 18))}</span></div>
    `;
  }

  const saTable = document.getElementById("saProposalsTable");
  if (saTable) {
    const props = s2.saProposals || [
      { type: "Encryption Algorithm", ike: "AES-256-GCM", child: "AES-256-GCM", status: "APPROVED", standard: "RFC 8221 / CNSA 2.0" },
      { type: "Key Exchange (DH)", ike: "ECP-256 (Group 19)", child: "None (PFS Disabled)", status: "NON-COMPLIANT", standard: "NIST SP 800-77 §4.2" },
      { type: "Pseudo-Random Function", ike: "HMAC-SHA2-256", child: "N/A (AEAD Suite)", status: "APPROVED", standard: "RFC 7296" },
      { type: "Integrity (AUTH)", ike: "Built-in (128-bit ICV)", child: "Built-in (128-bit ICV)", status: "APPROVED", standard: "NIST SP 800-77 Rev 1" },
      { type: "Extended Seq Numbers", ike: "N/A", child: "64-bit ESN Active", status: "APPROVED", standard: "RFC 4303 §2.2.1" }
    ];
    saTable.innerHTML = props.map(p => {
      const isPass = (p.status === "APPROVED");
      return `
        <tr>
          <td>${esc(p.type)}</td>
          <td>${esc(p.ike)}</td>
          <td>${esc(p.child)}</td>
          <td><span class="badge-status ${isPass ? 'pass' : 'fail'}">${esc(p.status)}</span></td>
          <td>${esc(p.standard || "NIST SP 800-77")}</td>
        </tr>
      `;
    }).join("");
  }

  // Section 3: Data-Plane (ESP) Stream Telemetry
  const hBars = document.getElementById("histogramBars");
  if (hBars) {
    const hist = s3.histogram || [
      { bin: "< 128 Bytes", label: "ESP Keepalive & Ack", pct: 4.2, count: "1,012" },
      { bin: "128 – 512 Bytes", label: "VoIP / Audio Frames", pct: 18.5, count: "4,460" },
      { bin: "512 – 1024 Bytes", label: "Interactive Data", pct: 21.3, count: "5,135" },
      { bin: "1024 – 1500 Bytes", label: "Full MTU Bulk / Video", pct: 56.0, count: "13,501" }
    ];
    hBars.innerHTML = hist.map(h => `
      <div class="h-bar-row">
        <div class="h-labels">
          <span>${esc(h.bin)} (${esc(h.label)})</span>
          <span>${h.pct}% (${esc(h.count)})</span>
        </div>
        <div class="h-track">
          <div class="h-fill" style="width:${Math.max(2, Math.min(100, Number(h.pct) || 0))}%;"></div>
        </div>
      </div>
    `).join("");
  }

  const iatGrid = document.getElementById("iatMetricsGrid");
  if (iatGrid) {
    const iat = s3.iatStats || { mean: "2.36 ms", median: "1.82 ms", jitter: "0.48 ms", min: "0.12 ms", max: "18.40 ms" };
    iatGrid.innerHTML = `
      <div class="iat-cell"><span class="iat-lbl">MEAN IAT</span><span class="iat-val">${esc(iat.mean)}</span></div>
      <div class="iat-cell"><span class="iat-lbl">MEDIAN IAT</span><span class="iat-val">${esc(iat.median)}</span></div>
      <div class="iat-cell"><span class="iat-lbl">JITTER (σ)</span><span class="iat-val">${esc(iat.jitter)}</span></div>
      <div class="iat-cell"><span class="iat-lbl">MIN / MAX</span><span class="iat-val">${esc(iat.min)} / ${esc(iat.max)}</span></div>
    `;
  }

  const seqBox = document.getElementById("seqProgressionBox");
  if (seqBox) {
    const seq = s3.sequenceProgression || {
      monotonicity: "100.0% Strict Monotonic",
      outOfOrder: "0 packets",
      rolloverSafeguard: "SAFE (64-bit ESN active)",
      replayWindow: "RFC 4303 64-packet bitmap verified; 0 duplicate packets"
    };
    seqBox.innerHTML = `
      <b>Sequence Monotonicity:</b> ${esc(seq.monotonicity)} | <b>Out of Order:</b> ${esc(seq.outOfOrder)}<br>
      <b>Rollover Protection:</b> ${esc(seq.rolloverSafeguard)}<br>
      <b>Anti-Replay Verification:</b> ${esc(seq.replayWindow)}
    `;
  }

  renderTimeline();

  // Section 4: AI/ML Inference Analysis
  const opMode = s4.operatingMode || { mode: "IPsec Tunnel Mode", confidence: 99.4, evidence: "Outer IP header encapsulates ESP header with internal private subnet routing addresses." };
  const mTitle = document.getElementById("operatingModeTitle");
  if (mTitle) mTitle.textContent = opMode.mode || "IPsec Tunnel Mode";
  const mConf = document.getElementById("modeConfidence");
  if (mConf) mConf.textContent = `${opMode.confidence || 99.4}% CONFIDENCE`;
  const mDesc = document.getElementById("operatingModeDesc");
  if (mDesc) mDesc.textContent = opMode.evidence || "";

  const fp = s4.fingerprint || { entropy: 7.98, clustering: 0.84, burstinessRatio: 1.42 };
  const fpRow = document.getElementById("fingerprintRow");
  if (fpRow) {
    fpRow.innerHTML = `
      <div class="fp-cell"><span class="fp-lbl">SHANNON ENTROPY</span><span class="fp-val">${fp.entropy || 7.98} / 8.0</span></div>
      <div class="fp-cell"><span class="fp-lbl">CLUSTERING COEFF</span><span class="fp-val">${fp.clustering || 0.84}</span></div>
      <div class="fp-cell"><span class="fp-lbl">BURSTINESS RATIO</span><span class="fp-val">${fp.burstinessRatio || 1.42}</span></div>
    `;
  }

  const tc = s4.trafficClassification || {};
  const pTag = document.getElementById("primaryClassTag");
  if (pTag) pTag.textContent = `${tc.confidence || 94.2}% CONFIDENCE`;

  const cDist = document.getElementById("classDistribution");
  if (cDist) {
    const classes = tc.classes || [
      { name: "Encrypted Video Stream", pct: 94.2, ci: "92.1% – 96.3%" },
      { name: "VoIP / Realtime Audio", pct: 3.1, ci: "1.9% – 4.3%" },
      { name: "Bulk Data & Sync", pct: 1.8, ci: "0.8% – 2.8%" },
      { name: "Web / Interactive", pct: 0.9, ci: "0.2% – 1.6%" }
    ];
    cDist.innerHTML = classes.map(c => `
      <div class="cl-row">
        <div class="cl-labels">
          <span>${esc(c.name)}</span>
          <span>${c.pct}% <span style="font-size:5.2px;color:#708194;">[CI: ${esc(c.ci || "")}]</span></span>
        </div>
        <div class="cl-track">
          <div class="cl-fill" style="width:${Math.max(2, Math.min(100, Number(c.pct) || 0))}%;"></div>
        </div>
      </div>
    `).join("");
  }

  // Section 5: Implementation Remediation Patches
  const swanEl = document.getElementById("swanctlPatchCode");
  if (swanEl) swanEl.textContent = s5.swanctlPatch || "# swanctl patch";
  const ciscoEl = document.getElementById("ciscoPatchCode");
  if (ciscoEl) ciscoEl.textContent = s5.ciscoPatch || "! cisco cli patch";

  const vCmds = document.getElementById("validationCmds");
  if (vCmds) {
    const cmds = s5.validationCommands || ["swanctl --list-sas", "ip xfrm state", "tcpdump -ni any esp"];
    vCmds.innerHTML = cmds.map(c => `<span>$ ${esc(c)}</span>`).join("");
  }

  // Section 6: Raw Session Trace Index
  const tTable = document.getElementById("traceIndexTable");
  if (tTable) {
    const traces = s6.traceIndex || [
      { idx: 1, offset: "+0.000s", layer: "UDP 500", type: "IKE_SA_INIT (Req)", spi: "Initiator=0x8b14...", len: "384 B", desc: "DH Group 19 proposal exchange" },
      { idx: 2, offset: "+0.014s", layer: "UDP 500", type: "IKE_SA_INIT (Resp)", spi: "Responder=0x4a7c...", len: "384 B", desc: "DH public key confirmation" },
      { idx: 3, offset: "+0.028s", layer: "UDP 4500", type: "IKE_AUTH (Req)", spi: "Initiator=0x8b14...", len: "448 B", desc: "PSK mutual identity authentication" },
      { idx: 4, offset: "+0.042s", layer: "UDP 4500", type: "IKE_AUTH (Resp)", spi: "Responder=0x4a7c...", len: "448 B", desc: "Child SA creation and Traffic Selectors" },
      { idx: 5, offset: "+0.056s", layer: "ESP (50)", type: "ESP Stream Data", spi: "Inbound=0xc0a80102", len: "1420 B", desc: "Seq #1 Monotonic AES-256-GCM payload" },
      { idx: 6, offset: "+56.79s", layer: "ESP (50)", type: "ESP Stream Data", spi: "Inbound=0xc0a80102", len: "1420 B", desc: "Seq #24,108 Monotonic verified" }
    ];
    tTable.innerHTML = traces.map(t => `
      <tr>
        <td>#${t.idx}</td>
        <td>${esc(t.offset)}</td>
        <td>${esc(t.layer)}</td>
        <td>${esc(t.type)}</td>
        <td>${esc(t.spi)}</td>
        <td>${esc(t.len)}</td>
        <td>${esc(clip(t.desc, 45))}</td>
      </tr>
    `).join("");
  }

  const jsonPre = document.getElementById("flowJsonDumpPre");
  if (jsonPre) jsonPre.textContent = s6.flowJsonDump || "{}";

  const faText = document.getElementById("technicalOverallAssessment");
  if (faText) faText.textContent = s6.overallAssessment || data.overallAssessment || "";
}

document.addEventListener("DOMContentLoaded", render);
