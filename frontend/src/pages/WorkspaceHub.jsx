import React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  FileCode,
  Radio,
  ArrowRight,
  CheckCircle2,
  Activity
} from 'lucide-react'

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
      {/* Minimal Topbar */}
      <header className="hub-topbar">
        <div className="hub-brand">
          <div className="brand-mark">
            <ShieldCheck size={18} color="var(--accent-blue)" />
          </div>
          <div className="hub-brand-text">
            <span className="hub-title">IPsec <em>Intelligence Platform</em></span>
          </div>
        </div>

        <div className="hub-status-strip">
          <div className="hub-status-pill">
            <span className="hub-led active" />
            <span>System Ready</span>
          </div>
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="hub-main">
        <div className="hub-hero">
          <h1>Select Operational Mode</h1>
          <p>
            Choose an analysis environment to inspect, audit, and profile IPsec VPN tunnels.
          </p>
        </div>

        {/* Dual Mode Selection Cards */}
        <div className="hub-modes-grid">
          {/* Mode 1: Forensic PCAP Analysis */}
          <div
            className="hub-mode-card"
            onClick={() => handleLaunchPcap()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && handleLaunchPcap()}
          >
            <div className="hub-card-header">
              <div className="hub-card-icon forensic">
                <FileCode size={24} color="var(--accent-blue)" />
              </div>
              <span className="hub-card-badge operational">PCAP Forensics</span>
            </div>

            <div className="hub-card-body">
              <h2>Forensic File Analysis</h2>
              <p className="hub-card-desc">
                Deterministic IKE handshake audit with 6-pillar NIST SP 800-77 evaluation and AI flow classification.
              </p>

              <div className="hub-symbolic-tags">
                <span className="hub-tag"><CheckCircle2 size={13} color="var(--accent-blue)" /> IKE Dissection</span>
                <span className="hub-tag"><CheckCircle2 size={13} color="var(--accent-blue)" /> NIST SP 800-77</span>
                <span className="hub-tag"><CheckCircle2 size={13} color="var(--accent-blue)" /> AI Flow Classifier</span>
              </div>
            </div>

            <div className="hub-card-footer">
              <button
                className="hub-btn primary"
                onClick={(e) => {
                  e.stopPropagation()
                  handleLaunchPcap()
                }}
              >
                <span>Launch Forensic Workspace</span>
                <ArrowRight size={15} />
              </button>
            </div>
          </div>

          {/* Mode 2: Real-Time Live Stream Analysis */}
          <div
            className="hub-mode-card realtime"
            onClick={handleLaunchRealtime}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && handleLaunchRealtime()}
          >
            <div className="hub-card-header">
              <div className="hub-card-icon realtime">
                <Radio size={24} color="var(--accent-cyan)" />
              </div>
              <span className="hub-card-badge staging">Live Stream</span>
            </div>

            <div className="hub-card-body">
              <h2>Real-Time Stream Monitor</h2>
              <p className="hub-card-desc">
                Continuous network wiretap, real-time ESP telemetry, sequence anomaly detection, and live threat evaluation.
              </p>

              <div className="hub-symbolic-tags">
                <span className="hub-tag"><Activity size={13} color="var(--accent-cyan)" /> Live Telemetry</span>
                <span className="hub-tag"><Activity size={13} color="var(--accent-cyan)" /> Multi-Link Mesh</span>
                <span className="hub-tag"><Activity size={13} color="var(--accent-cyan)" /> Threat Alerts</span>
              </div>
            </div>

            <div className="hub-card-footer">
              <button
                className="hub-btn cyan"
                onClick={(e) => {
                  e.stopPropagation()
                  handleLaunchRealtime()
                }}
              >
                <span>Open Real-Time Cockpit</span>
                <ArrowRight size={15} />
              </button>
            </div>
          </div>
        </div>

        {/* Minimal Footer */}
        <footer className="hub-footer">
          <span>NIST SP 800-77 Rev. 1 &bull; NSA CNSA 2.0 Cryptographic Evaluation Engine</span>
        </footer>
      </main>
    </div>
  )
}
