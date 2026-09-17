import React, { useState } from 'react'
import Header from '../components/Header'
import GlassCard from '../components/GlassCard'
import SecurityScore from '../components/SecurityScore'
import PcapIngestion from '../components/PcapIngestion'
import CryptoAuditPanel from '../components/CryptoAuditPanel'
import TrafficIntelligencePanel from '../components/TrafficIntelligencePanel'
import TimelineSlices from '../components/TimelineSlices'
import ReportExportModal from '../components/ReportExportModal'
import { FileText, Loader2 } from 'lucide-react'

export default function Dashboard({
  security,
  connection,
  theme,
  toggleTheme,
  activeFilename,
  isAnalyzing,
  error,
  onUploadFile,
  auditData,
  ikeDetails,
  aiData,
  execSummary
}) {
  const [isReportModalOpen, setIsReportModalOpen] = useState(false)

  return (
    <>
      <Header
        connection={connection}
        theme={theme}
        toggleTheme={toggleTheme}
      />

      <main className="shell" style={{ paddingTop: '70px' }}>
        {/* Ingestion Section - strictly PCAP/PCAPNG, unanalyzed on mount */}
        <div id="ingestion">
          <PcapIngestion
            onUploadFile={onUploadFile}
            isAnalyzing={isAnalyzing}
            activeFilename={activeFilename}
          />
        </div>

        {/* Analyzing Progress State */}
        {isAnalyzing && (
          <div style={{
            marginTop: '1.25rem',
            padding: '2.5rem 1.5rem',
            background: 'var(--glass-inner)',
            border: '1px solid var(--border)',
            borderRadius: '12px',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '0.75rem'
          }}>
            <Loader2 size={32} className="spin" color="var(--accent-blue)" />
            <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Dissecting IPsec Capture...
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Executing RFC transform extraction and statistical flow inference
            </div>
          </div>
        )}

        {/* Analysis Section - ONLY appears once a file is uploaded */}
        {auditData && !isAnalyzing && (
          <>
            {/* Security Scorecard & Profiling Summary */}
            <div id="security" style={{ marginTop: '1.25rem', marginBottom: '1rem' }}>
              <GlassCard className="combo-card">
                <div className="combo-half">
                  <SecurityScore
                    score={security?.riskScore}
                    rawScore={security?.rawScore}
                    vetoCeiling={security?.vetoCeiling}
                    level={security?.riskLevel}
                    anomaly={security?.anomalyDetected}
                    postureLabel={security?.postureLabel}
                    complianceStatus={security?.complianceStatus}
                  />
                </div>

                <div className="combo-divider" />

                <div className="combo-half">
                  <div className="card-title-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div className="section-kicker">WIRETAP TELEMETRY</div>
                      <h3 style={{ margin: '2px 0 0', fontSize: '0.98rem', fontWeight: 700 }}>
                        Active Capture Profiling
                      </h3>
                    </div>
                    <button
                      type="button"
                      onClick={() => setIsReportModalOpen(true)}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        padding: '6px 14px',
                        borderRadius: '8px',
                        background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(37, 99, 235, 0.25))',
                        border: '1px solid rgba(56, 189, 248, 0.4)',
                        color: '#38bdf8',
                        fontSize: '0.82rem',
                        fontWeight: 700,
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                    >
                      <FileText size={14} /> Export Report
                    </button>
                  </div>

                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(2, 1fr)',
                    gap: '0.65rem',
                    marginTop: '0.85rem'
                  }}>
                    <div style={{
                      padding: '0.75rem 0.95rem',
                      background: 'var(--glass-inner)',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)'
                    }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Target PCAP</div>
                      <div style={{ fontSize: '1.02rem', fontWeight: 700, color: 'var(--accent-blue)', wordBreak: 'break-all', marginTop: 3 }}>
                        {activeFilename || execSummary?.target_pcap || 'Capture'}
                      </div>
                    </div>

                    <div style={{
                      padding: '0.75rem 0.95rem',
                      background: 'var(--glass-inner)',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)'
                    }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Packets</div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 3 }}>
                        {execSummary?.total_packets || 0} frames
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 6 }}>
                          ({execSummary?.esp_packets || 0} ESP)
                        </span>
                      </div>
                    </div>

                    <div style={{
                      padding: '0.75rem 0.95rem',
                      background: 'var(--glass-inner)',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)'
                    }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Session Duration</div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 3 }}>
                        {execSummary?.session_duration_sec ? `${Number(execSummary.session_duration_sec).toFixed(1)}s` : '0.0s'}
                      </div>
                    </div>

                    <div style={{
                      padding: '0.75rem 0.95rem',
                      background: 'var(--glass-inner)',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)'
                    }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Throughput</div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 3 }}>
                        {((aiData?.average_bytes_sec || 0) / 1024).toFixed(1)} KB/s
                      </div>
                    </div>
                  </div>

                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginTop: '0.85rem',
                    padding: '0.6rem 0.85rem',
                    background: 'var(--glass-inner)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)'
                  }}>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active SPI Pair:</span>
                    <span style={{ fontSize: '0.85rem', fontFamily: 'monospace', color: 'var(--accent-blue)', fontWeight: 700 }}>
                      {execSummary?.spi_pair || 'None Observed'}
                    </span>
                  </div>
                </div>
              </GlassCard>
            </div>

            {/* Deterministic Cryptographic Audit Panel */}
            <div id="audit" style={{ marginBottom: '1rem' }}>
              <CryptoAuditPanel
                auditData={auditData}
                ikeDetails={ikeDetails}
                execSummary={execSummary}
              />
            </div>

            {/* AI Encrypted Traffic Intelligence Panel */}
            <div id="ai-telemetry" style={{ marginBottom: '1rem' }}>
              <TrafficIntelligencePanel aiData={aiData} />
            </div>

            {/* Sliding Window Temporal Breakdown */}
            <div id="timeline">
              <TimelineSlices slices={aiData?.temporal_window_breakdown || []} />
            </div>
          </>
        )}

        <footer style={{
          textAlign: 'center',
          fontSize: '0.72rem',
          color: 'var(--text-muted)',
          padding: '1.75rem 0 1rem'
        }}>
          ApexVigil IPsec Intelligence Platform &bull; NIST SP 800-77 Rev. 1 &bull; NSA CNSA 2.0
        </footer>
      </main>

      {/* Intelligence Report Generator Modal */}
      <ReportExportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        mode="pcap"
        pcapFilename={activeFilename || execSummary?.target_pcap || 'Capture'}
        activeData={auditData ? {
          pcap_file: activeFilename || 'capture.pcap',
          executive_summary: execSummary,
          cryptographic_audit: auditData,
          ike_protocol_details: ikeDetails,
          ai_traffic_intelligence: aiData
        } : null}
      />
    </>
  )
}
