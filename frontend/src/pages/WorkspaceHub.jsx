import React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  FileCode,
  Radio,
  Cpu,
  Terminal,
  Activity,
  ArrowRight,
  Database,
  Lock,
  Wifi,
  ExternalLink,
  Layers,
  Sparkles
} from 'lucide-react'
import GlassCard from '../components/GlassCard'

export default function WorkspaceHub({
  connection = 'LIVE',
  samples = [],
  onSelectSample,
  tournamentData
}) {
  const navigate = useNavigate()

  const handleLaunchPcap = (sampleId = null) => {
    if (sampleId && onSelectSample) {
      onSelectSample(sampleId)
    }
    navigate('/pcap')
  }

  const handleLaunchRealtime = () => {
    navigate('/realtime')
  }

  return (
    <div className="hub-container">
      {/* Workstation Top Command Bar */}
      <header className="hub-topbar">
        <div className="hub-brand">
          <div className="brand-mark">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="hub-title">
              NTRO IPsec <em>Intelligence Platform</em>
            </div>
            <div className="hub-meta">
              SIH26160 · Cyber Defense &amp; Cryptographic Warfare Workstation
            </div>
          </div>
        </div>

        <div className="hub-status-strip">
          <div className="hub-status-item">
            <span className="hub-led active" />
            <span>BACKEND: <strong>127.0.0.1:8000</strong></span>
          </div>
          <div className="hub-status-item">
            <Lock size={12} color="var(--accent-green)" />
            <span>MODE: <strong>AIR-GAPPED OFFLINE</strong></span>
          </div>
          <div className="hub-status-item">
            <Cpu size={12} color="var(--accent-blue)" />
            <span>AI: <strong>HistGradientBoosting (80.5%)</strong></span>
          </div>
        </div>
      </header>

      {/* Main Hub Body */}
      <main className="hub-main">
        <div className="hub-hero">
          <div className="hub-eyebrow">
            <Sparkles size={13} color="var(--accent-blue)" />
            <span>MISSION SPECIFICATION · WORKSTATION DISPATCH</span>
          </div>
          <h1>Select Operational Analysis Mode</h1>
          <p>
            Autonomous cryptographic compliance auditing, wiretap packet dissection, and
            AI-driven encrypted flow profiling for IPsec VPN infrastructures.
          </p>
        </div>

        {/* Dual Mode Cards Grid */}
        <div className="hub-modes-grid">
          {/* Mode 1: Forensic PCAP Analysis */}
          <GlassCard className="hub-mode-card active-card">
            <div className="hub-card-header">
              <div className="hub-card-icon forensic">
                <FileCode size={26} color="var(--accent-blue)" />
              </div>
              <div className="hub-card-badge operational">
                PRODUCTION OPERATIONAL
              </div>
            </div>

            <div className="hub-card-content">
              <h2>Forensic PCAP File Analysis</h2>
              <p className="hub-card-desc">
                Deterministic IKEv1/IKEv2 handshake dissection, 6-pillar NIST SP 800-77 Rev. 1
                compliance audit with non-compensatory Veto Ceiling (C_cap), and 48-feature
                AI flow classification on recorded <code>.pcap</code> / <code>.pcapng</code> captures.
              </p>

              <div className="hub-features-list">
                <div className="hub-feature-item">
                  <span className="dot blue" />
                  <span>IKE Transform &amp; SA Proposal Dissection (Phase 1 &amp; Phase 2)</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot blue" />
                  <span>NIST SP 800-77 &amp; CNSA 2.0 Scoring Rubric (Sweet32, Logjam, SHAttered)</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot blue" />
                  <span>Dual-Champion AI Engine: Traffic Profile + Tunnel/Transport Mode</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot blue" />
                  <span>Bimodal Flow Telemetry &amp; Sliding-Window Pacing (1.5s windows)</span>
                </div>
              </div>

              {/* Quick Launch Presets */}
              <div className="hub-presets-section">
                <div className="presets-title">QUICK-LOAD VERIFIED SCENARIOS:</div>
                <div className="presets-chips">
                  <button
                    className="preset-chip"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleLaunchPcap('golden_audit')
                    }}
                  >
                    <span>Golden IKEv2 (Pass)</span>
                  </button>
                  <button
                    className="preset-chip danger"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleLaunchPcap('vulnerable_3des')
                    }}
                  >
                    <span>3DES Sweet32 (Fail)</span>
                  </button>
                  <button
                    className="preset-chip warning"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleLaunchPcap('midstream_wiretap')
                    }}
                  >
                    <span>Mid-Stream ESP</span>
                  </button>
                  <button
                    className="preset-chip info"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleLaunchPcap('concurrent_mixed')
                    }}
                  >
                    <span>Multiplexed VoIP+Bulk</span>
                  </button>
                </div>
              </div>
            </div>

            <div className="hub-card-footer">
              <button
                className="hub-btn primary"
                onClick={() => handleLaunchPcap()}
              >
                <span>Launch Forensic Workspace</span>
                <ArrowRight size={16} />
              </button>
            </div>
          </GlassCard>

          {/* Mode 2: Real-Time Live Stream Analysis */}
          <GlassCard className="hub-mode-card realtime-card">
            <div className="hub-card-header">
              <div className="hub-card-icon realtime">
                <Radio size={26} color="var(--accent-cyan)" />
              </div>
              <div className="hub-card-badge staging">
                STAGING · READY TO HOOK
              </div>
            </div>

            <div className="hub-card-content">
              <h2>Real-Time Live Stream Analysis</h2>
              <p className="hub-card-desc">
                Promiscuous live network wiretap on local network adapters, Docker bridges, or
                hardware taps. Streams real-time ESP telemetry, detects active sequence anomalies,
                and executes live inference on active cryptographic tunnels.
              </p>

              <div className="hub-features-list">
                <div className="hub-feature-item">
                  <span className="dot cyan" />
                  <span>Continuous Async Interface Sniffing (Scapy / libpcap engine)</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot cyan" />
                  <span>Live Sliding-Window Signal Feature Extraction &amp; Rolling Telemetry</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot cyan" />
                  <span>Real-Time Anti-Replay Sliding Window Gap &amp; Loss Detection</span>
                </div>
                <div className="hub-feature-item">
                  <span className="dot cyan" />
                  <span>Autonomous Threat Event Triggering &amp; Wiretap Stream Alerts</span>
                </div>
              </div>

              {/* Adapter Preview Box */}
              <div className="hub-presets-section">
                <div className="presets-title">TARGET PROMISCUOUS INTERFACES:</div>
                <div className="adapter-preview-grid">
                  <div className="adapter-chip active">
                    <span className="pulse-mini" />
                    <span>br-ipsec (172.28.0.0/16)</span>
                  </div>
                  <div className="adapter-chip">
                    <Wifi size={12} />
                    <span>Host Ethernet / Wi-Fi</span>
                  </div>
                  <div className="adapter-chip">
                    <Layers size={12} />
                    <span>TAP / Virtual TUN</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="hub-card-footer">
              <button
                className="hub-btn cyan"
                onClick={handleLaunchRealtime}
              >
                <span>Open Real-Time Cockpit</span>
                <ArrowRight size={16} />
              </button>
            </div>
          </GlassCard>
        </div>

        {/* Engineering Diagnostics Strip */}
        <div className="hub-diagnostics-bar">
          <div className="diag-group">
            <span className="diag-label">SYSTEM KERNEL:</span>
            <span className="diag-val">Linux / Windows NT Native</span>
          </div>
          <div className="diag-divider" />
          <div className="diag-group">
            <span className="diag-label">NIST COMPLIANCE SPEC:</span>
            <span className="diag-val">NIST SP 800-77 Rev. 1 &amp; CNSA 2.0</span>
          </div>
          <div className="diag-divider" />
          <div className="diag-group">
            <span className="diag-label">ENGINE ACCURACY:</span>
            <span className="diag-val">Mode 95.44% · Traffic 80.50% F1</span>
          </div>
          <div className="diag-divider" />
          <div className="diag-group">
            <span className="diag-label">SECURITY POSTURE:</span>
            <span className="diag-val highlight">AIR-GAPPED DEFENSE GRADE</span>
          </div>
        </div>
      </main>
    </div>
  )
}
