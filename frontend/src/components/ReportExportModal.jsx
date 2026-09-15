import React, { useState, useEffect } from 'react'
import {
  FileText,
  ShieldCheck,
  Cpu,
  Download,
  ExternalLink,
  Printer,
  X,
  Layers,
  Clock,
  CheckCircle,
  AlertCircle,
  Sliders,
  Network
} from 'lucide-react'
import { API_BASE } from '../services/api'

export default function ReportExportModal({
  isOpen,
  onClose,
  mode = 'pcap', // 'pcap' | 'live'
  pcapFilename = 'sih26_asim_golden.pcap',
  activeData = null,
  links = [],
  elapsedSeconds = 15
}) {
  const [reportType, setReportType] = useState('executive') // 'executive' | 'security' | 'technical'
  const [scope, setScope] = useState('overall')
  const [timeframeMode, setTimeframeMode] = useState('full') // 'full' | 'window'
  const [startSec, setStartSec] = useState(0)
  const [endSec, setEndSec] = useState(Math.max(5, Math.round(elapsedSeconds)))
  const [isGenerating, setIsGenerating] = useState(false)
  const [generatedReport, setGeneratedReport] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (isOpen) {
      setGeneratedReport(null)
      setError(null)
      setEndSec(Math.max(5, Math.round(elapsedSeconds)))
    }
  }, [isOpen, elapsedSeconds])

  if (!isOpen) return null

  const handleGenerate = async (autoOpen = false) => {
    setIsGenerating(true)
    setError(null)

    try {
      const payload = {
        report_type: reportType,
        analysis_type: mode,
        scope: mode === 'live' ? scope : 'overall',
        timeframe: mode === 'live' ? {
          mode: timeframeMode,
          start_sec: Number(startSec),
          end_sec: Number(endSec)
        } : { mode: 'full' },
        pcap_filename: pcapFilename,
        data: activeData
      }

      const res = await fetch(API_BASE + '/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}))
        throw new Error(errJson.detail || `Server returned error ${res.status}`)
      }

      const result = await res.json()
      setGeneratedReport(result)

      if (autoOpen) {
        const targetUrl = result.has_pdf && result.pdf_url ? result.pdf_url : result.view_url
        window.open(API_BASE.replace(/\/api$/, '') + targetUrl, '_blank')
      }
    } catch (err) {
      console.error('Report generation failed:', err)
      setError(err.message || 'Failed to generate report')
    } finally {
      setIsGenerating(false)
    }
  }

  const reportTiers = [
    {
      id: 'executive',
      name: 'Executive Risk Briefing',
      kicker: 'STRATEGIC CISO BRIEFING',
      desc: 'High-level strategic risk evaluation, dynamic risk index gauge (0-100), 4 key operational KPIs, threat quadrant matrix, and 90-day remediation roadmap.',
      icon: <FileText size={20} color="#38bdf8" />,
      tag: 'CISO / LEADERSHIP'
    },
    {
      id: 'security',
      name: 'Security Assessment Report',
      kicker: 'CRYPTOGRAPHIC AUDIT & RFC COMPLIANCE',
      desc: 'Deep 6-pillar cryptographic compliance audit against NIST SP 800-77 Rev 1, domain weightage, itemized penalty deductions, CVE defects, and posture projections.',
      icon: <ShieldCheck size={20} color="#34d399" />,
      tag: 'NIST SP 800-77 AUDIT'
    },
    {
      id: 'technical',
      name: 'Technical Protocol Report',
      kicker: 'ENGINEERING PROTOCOL DISSECTION',
      desc: 'Packet-level temporal waveform, ESP sequence telemetry, inner AI traffic classification distribution (LightGBM champion), SPI tracking, and cipher proposal negotiation.',
      icon: <Cpu size={20} color="#a78bfa" />,
      tag: 'DEEP PROTOCOL TELEMETRY'
    }
  ]

  const baseOrigin = API_BASE.replace(/\/api$/, '')

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(5, 10, 30, 0.84)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        zIndex: 10000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem'
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'rgba(15, 23, 42, 0.94)',
          border: '1px solid rgba(255, 255, 255, 0.16)',
          borderRadius: '16px',
          boxShadow: '0 24px 64px rgba(0, 0, 0, 0.7), 0 0 40px rgba(56, 189, 248, 0.12)',
          maxWidth: '840px',
          width: '100%',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '1.75rem',
          color: 'var(--text-primary)'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.1)', paddingBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{
              width: 40,
              height: 40,
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(56, 189, 248, 0.05))',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <FileText size={22} color="#38bdf8" />
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', letterSpacing: '0.08em', color: '#38bdf8', fontWeight: 700, textTransform: 'uppercase' }}>
                {mode === 'pcap' ? 'FORENSIC AUDIT GENERATOR' : 'LIVE STREAM AUDIT GENERATOR'}
              </div>
              <h2 style={{ margin: '2px 0 0', fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#ffffff' }}>
                Generate Intelligence Report (PDF &amp; HTML)
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              borderRadius: '8px',
              width: 32,
              height: 32,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              color: '#94a3b8'
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Target Info Banner */}
        <div style={{
          marginTop: '1.25rem',
          padding: '0.85rem 1.15rem',
          background: 'rgba(30, 41, 59, 0.55)',
          borderRadius: '10px',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.82rem'
        }}>
          <div>
            <span style={{ color: '#94a3b8' }}>Target Source: </span>
            <strong style={{ color: '#ffffff' }}>
              {mode === 'pcap' ? pcapFilename : `Real-Time Simulation (${links.length || 3} Links)`}
            </strong>
          </div>
          <div style={{ display: 'flex', gap: '0.85rem', color: '#94a3b8' }}>
            {mode === 'pcap' ? (
              <span>Timeframe: <strong style={{ color: '#34d399' }}>Full Capture Duration</strong></span>
            ) : (
              <span>Elapsed: <strong style={{ color: '#38bdf8' }}>{Math.round(elapsedSeconds)}s continuous</strong></span>
            )}
          </div>
        </div>

        {/* Step 1: Select Report Tier */}
        <div style={{ marginTop: '1.35rem' }}>
          <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
            1. Select Report Tier
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
            {reportTiers.map(tier => {
              const isSelected = reportType === tier.id
              return (
                <div
                  key={tier.id}
                  onClick={() => setReportType(tier.id)}
                  style={{
                    padding: '1rem',
                    borderRadius: '12px',
                    background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                    border: isSelected ? '1.5px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      {tier.icon}
                      <span style={{ fontSize: '0.62rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: isSelected ? 'rgba(56, 189, 248, 0.25)' : 'rgba(255, 255, 255, 0.08)', color: isSelected ? '#38bdf8' : '#94a3b8' }}>
                        {tier.tag}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.68rem', fontWeight: 700, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      {tier.kicker}
                    </div>
                    <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff', marginTop: '2px' }}>
                      {tier.name}
                    </div>
                    <p style={{ fontSize: '0.73rem', color: '#94a3b8', marginTop: '0.45rem', lineHeight: '1.4' }}>
                      {tier.desc}
                    </p>
                  </div>
                  {isSelected && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginTop: '0.75rem', fontSize: '0.72rem', color: '#38bdf8', fontWeight: 600 }}>
                      <CheckCircle size={14} /> Selected Tier
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Step 2 (Live Mode only): Scope & Timeframe Selection */}
        {mode === 'live' && (
          <div style={{ marginTop: '1.35rem', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1rem' }}>
            {/* Scope Selection */}
            <div>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.65rem' }}>
                2. Analysis Scope
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                <div
                  onClick={() => setScope('overall')}
                  style={{
                    padding: '0.65rem 0.85rem',
                    borderRadius: '8px',
                    background: scope === 'overall' ? 'rgba(56, 189, 248, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                    border: scope === 'overall' ? '1px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '0.82rem'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <Network size={16} color="#38bdf8" />
                    <div>
                      <div style={{ fontWeight: 700, color: '#ffffff' }}>Overall Network Mesh</div>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Aggregate across all {links.length || 3} active tunnels</div>
                    </div>
                  </div>
                  {scope === 'overall' && <CheckCircle size={16} color="#38bdf8" />}
                </div>

                {links.map(lnk => {
                  const isSelected = scope === lnk.id
                  return (
                    <div
                      key={lnk.id}
                      onClick={() => setScope(lnk.id)}
                      style={{
                        padding: '0.65rem 0.85rem',
                        borderRadius: '8px',
                        background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(30, 41, 59, 0.45)',
                        border: isSelected ? '1px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: '0.82rem'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                        <Layers size={16} color={isSelected ? '#38bdf8' : '#94a3b8'} />
                        <div>
                          <div style={{ fontWeight: 700, color: '#ffffff' }}>{lnk.name}</div>
                          <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>
                            {lnk.crypto?.encryption || 'AES-256-GCM'} · {lnk.operating_mode?.toUpperCase()}
                          </div>
                        </div>
                      </div>
                      {isSelected && <CheckCircle size={16} color="#38bdf8" />}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Timeframe Selection */}
            <div>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.65rem' }}>
                3. Timeframe Window
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <button
                  type="button"
                  onClick={() => setTimeframeMode('full')}
                  style={{
                    flex: 1,
                    padding: '0.55rem',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    background: timeframeMode === 'full' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.45)',
                    border: timeframeMode === 'full' ? '1px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                    color: timeframeMode === 'full' ? '#ffffff' : '#94a3b8',
                    cursor: 'pointer'
                  }}
                >
                  Entire Connection (0s – {Math.round(elapsedSeconds)}s)
                </button>
                <button
                  type="button"
                  onClick={() => setTimeframeMode('window')}
                  style={{
                    flex: 1,
                    padding: '0.55rem',
                    borderRadius: '8px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    background: timeframeMode === 'window' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(30, 41, 59, 0.45)',
                    border: timeframeMode === 'window' ? '1px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                    color: timeframeMode === 'window' ? '#ffffff' : '#94a3b8',
                    cursor: 'pointer'
                  }}
                >
                  Custom Window Slicing
                </button>
              </div>

              {timeframeMode === 'window' ? (
                <div style={{ padding: '0.85rem', background: 'rgba(30, 41, 59, 0.55)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <div style={{ display: 'flex', gap: '0.85rem', alignItems: 'center' }}>
                    <div style={{ flex: 1 }}>
                      <label style={{ fontSize: '0.7rem', color: '#94a3b8', display: 'block', marginBottom: 4 }}>
                        Start Time (seconds)
                      </label>
                      <input
                        type="number"
                        min="0"
                        max={Math.max(1, endSec - 1)}
                        value={startSec}
                        onChange={(e) => setStartSec(Math.max(0, parseFloat(e.target.value) || 0))}
                        style={{
                          width: '100%',
                          padding: '6px 10px',
                          borderRadius: '6px',
                          background: 'rgba(15, 23, 42, 0.8)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          outline: 'none'
                        }}
                      />
                    </div>
                    <div style={{ flex: 1 }}>
                      <label style={{ fontSize: '0.7rem', color: '#94a3b8', display: 'block', marginBottom: 4 }}>
                        End Time (seconds)
                      </label>
                      <input
                        type="number"
                        min={startSec + 1}
                        max={Math.max(5, Math.round(elapsedSeconds) + 60)}
                        value={endSec}
                        onChange={(e) => setEndSec(Math.max(startSec + 1, parseFloat(e.target.value) || (startSec + 5)))}
                        style={{
                          width: '100%',
                          padding: '6px 10px',
                          borderRadius: '6px',
                          background: 'rgba(15, 23, 42, 0.8)',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          outline: 'none'
                        }}
                      />
                    </div>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: '#38bdf8', marginTop: '0.5rem' }}>
                    Active Slicing Duration: <strong>{Math.max(1, (endSec - startSec)).toFixed(1)} seconds</strong>
                  </div>
                </div>
              ) : (
                <div style={{ padding: '0.85rem', background: 'rgba(30, 41, 59, 0.3)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)', fontSize: '0.75rem', color: '#94a3b8' }}>
                  Audits the full lifetime duration of the live stream from inception to current tick.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Error Notification */}
        {error && (
          <div style={{
            marginTop: '1.25rem',
            padding: '0.75rem 1rem',
            borderRadius: '8px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            color: '#fca5a5',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {/* Success Confirmation Card if Generated */}
        {generatedReport && (
          <div style={{
            marginTop: '1.25rem',
            padding: '1.15rem',
            borderRadius: '12px',
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '1rem'
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#34d399', fontSize: '0.88rem', fontWeight: 700 }}>
                <CheckCircle size={17} /> Report Generated Successfully (PDF &amp; HTML)
              </div>
              <div style={{ fontSize: '0.75rem', color: '#cbd5e1', marginTop: 3 }}>
                Report ID: <strong style={{ color: '#ffffff' }}>{generatedReport.report_id}</strong> · {generatedReport.pdf_filename || generatedReport.filename}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '0.55rem', flexWrap: 'wrap' }}>
              {/* Direct PDF Actions */}
              {generatedReport.has_pdf && generatedReport.pdf_download_url ? (
                <a
                  href={`${baseOrigin}${generatedReport.pdf_download_url}`}
                  download
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 16px',
                    borderRadius: '9999px',
                    background: '#10b981',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '0.82rem',
                    fontWeight: 700,
                    textDecoration: 'none',
                    boxShadow: '0 4px 12px rgba(16, 185, 129, 0.35)',
                    cursor: 'pointer'
                  }}
                >
                  <Download size={14} /> Download PDF
                </a>
              ) : null}

              {generatedReport.has_pdf && generatedReport.pdf_url ? (
                <button
                  type="button"
                  onClick={() => window.open(`${baseOrigin}${generatedReport.pdf_url}`, '_blank')}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 14px',
                    borderRadius: '9999px',
                    background: '#2563eb',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '0.82rem',
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  <ExternalLink size={14} /> View PDF
                </button>
              ) : null}

              <button
                type="button"
                onClick={() => window.open(`${baseOrigin}${generatedReport.view_url}`, '_blank')}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 14px',
                  borderRadius: '9999px',
                  background: 'rgba(255, 255, 255, 0.1)',
                  color: '#ffffff',
                  border: '1px solid rgba(255, 255, 255, 0.15)',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                <Printer size={14} /> Web Report
              </button>
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div style={{ marginTop: '1.75rem', borderTop: '1px solid rgba(255, 255, 255, 0.1)', paddingTop: '1.25rem', display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '0.65rem 1.25rem',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.08)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#cbd5e1',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={isGenerating}
            onClick={() => handleGenerate(true)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.65rem 1.45rem',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              border: 'none',
              color: '#ffffff',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: isGenerating ? 'not-allowed' : 'pointer',
              opacity: isGenerating ? 0.7 : 1,
              boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)'
            }}
          >
            {isGenerating ? (
              <>Generating PDF &amp; HTML...</>
            ) : (
              <>
                <ExternalLink size={16} /> Generate &amp; Open PDF Report
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
