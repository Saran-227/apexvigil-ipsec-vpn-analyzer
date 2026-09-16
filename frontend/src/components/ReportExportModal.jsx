import React, { useState, useEffect, useRef } from 'react'
import {
  FileText,
  ShieldCheck,
  Cpu,
  X,
  CheckCircle,
  Network
} from 'lucide-react'
import { API_BASE } from '../services/api'

export default function ReportExportModal({
  isOpen,
  onClose,
  mode = 'pcap',
  pcapFilename = 'capture.pcap',
  activeData = null,
  links = [],
  initialScope = 'overall',
  onScopeChange = null,
  elapsedSeconds = 15
}) {
  const [reportType, setReportType] = useState('executive')
  const [scope, setScope] = useState(initialScope || 'overall')
  const [timeframeMode, setTimeframeMode] = useState('full')
  const [startSec, setStartSec] = useState(0)
  const [endSec, setEndSec] = useState(Math.max(5, Math.round(elapsedSeconds)))
  const [isGenerating, setIsGenerating] = useState(false)
  const [generatedReport, setGeneratedReport] = useState(null)
  const [error, setError] = useState(null)

  const prevIsOpenRef = useRef(false)

  useEffect(() => {
    // Only reset state when the modal transitions from closed to open
    if (isOpen && !prevIsOpenRef.current) {
      setGeneratedReport(null)
      setError(null)
      setScope(initialScope || 'overall')
      setEndSec(Math.max(5, Math.round(elapsedSeconds)))
    }
    prevIsOpenRef.current = isOpen
  }, [isOpen])

  const handleScopeSelect = (newScope) => {
    setScope(newScope)
    setGeneratedReport(null)
    if (onScopeChange) {
      onScopeChange(newScope === 'overall' ? 'all' : newScope)
    }
  }

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

  // Reports list - Just state the names of each report, no explanatory descriptions
  const reportTiers = [
    {
      id: 'executive',
      name: 'Executive Risk Briefing',
      icon: <FileText size={22} color="#38bdf8" />
    },
    {
      id: 'security',
      name: 'Security Assessment Report',
      icon: <ShieldCheck size={22} color="#34d399" />
    },
    {
      id: 'technical',
      name: 'Technical Protocol Report',
      icon: <Cpu size={22} color="#a78bfa" />
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
          maxWidth: '720px',
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
              width: 38,
              height: 38,
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(56, 189, 248, 0.05))',
              border: '1px solid rgba(56, 189, 248, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <FileText size={20} color="#38bdf8" />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: '#ffffff' }}>
                Generate Intelligence Report
              </h2>
              <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                Target: <strong style={{ color: '#ffffff' }}>{mode === 'live' ? (scope === 'overall' ? 'All Links (Network Aggregate)' : (links?.find(l => l.id === scope)?.name || (scope === 'link-1' ? 'Link 1: HQ Gateway ↔ Datacenter Core' : scope === 'link-2' ? 'Link 2: Tactical Edge ↔ Command HQ' : scope === 'link-3' ? 'Link 3: Field Recon ↔ Mission Hub' : scope))) : pcapFilename}</strong>
              </span>
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

        {/* Step: Analysis Scope Selection (Live Telemetry) */}
        {mode === 'live' && (
          <div style={{ marginTop: '1.25rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Network size={15} color="#38bdf8" />
              Analysis Scope:
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.6rem' }}>
              <button
                type="button"
                onClick={() => handleScopeSelect('overall')}
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: '10px',
                  background: scope === 'overall' ? 'rgba(56, 189, 248, 0.22)' : 'rgba(30, 41, 59, 0.45)',
                  border: scope === 'overall' ? '1.5px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                  color: scope === 'overall' ? '#ffffff' : '#94a3b8',
                  fontSize: '0.8rem',
                  fontWeight: scope === 'overall' ? 700 : 500,
                  cursor: 'pointer',
                  textAlign: 'center',
                  transition: 'all 0.15s ease',
                  boxShadow: scope === 'overall' ? '0 0 14px rgba(56, 189, 248, 0.25)' : 'none'
                }}
              >
                All Links (Aggregate)
              </button>
              {(links && links.length > 0 ? links : [
                { id: 'link-1', name: 'Link 1: HQ Gateway ↔ Datacenter Core' },
                { id: 'link-2', name: 'Link 2: Tactical Edge ↔ Command HQ' },
                { id: 'link-3', name: 'Link 3: Field Recon ↔ Mission Hub' }
              ]).map(lnk => {
                const isSelected = scope === lnk.id
                return (
                  <button
                    key={lnk.id}
                    type="button"
                    onClick={() => handleScopeSelect(lnk.id)}
                    style={{
                      padding: '0.65rem 0.85rem',
                      borderRadius: '10px',
                      background: isSelected ? 'rgba(56, 189, 248, 0.22)' : 'rgba(30, 41, 59, 0.45)',
                      border: isSelected ? '1.5px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                      color: isSelected ? '#ffffff' : '#94a3b8',
                      fontSize: '0.8rem',
                      fontWeight: isSelected ? 700 : 500,
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.15s ease',
                      boxShadow: isSelected ? '0 0 14px rgba(56, 189, 248, 0.25)' : 'none'
                    }}
                  >
                    {lnk.name || lnk.id}
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* Step 1: Select Report Tier - Names only */}
        <div style={{ marginTop: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.75rem' }}>
            Select Report:
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
            {reportTiers.map(tier => {
              const isSelected = reportType === tier.id
              return (
                <div
                  key={tier.id}
                  onClick={() => setReportType(tier.id)}
                  style={{
                    padding: '1.1rem 1rem',
                    borderRadius: '12px',
                    background: isSelected ? 'rgba(56, 189, 248, 0.15)' : 'rgba(30, 41, 59, 0.45)',
                    border: isSelected ? '1.5px solid #38bdf8' : '1px solid rgba(255, 255, 255, 0.08)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    textAlign: 'center',
                    gap: '0.65rem'
                  }}
                >
                  {tier.icon}
                  <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff', lineHeight: 1.3 }}>
                    {tier.name}
                  </div>
                  {isSelected ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.72rem', color: '#38bdf8', fontWeight: 700 }}>
                      <CheckCircle size={14} /> Selected
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
                      Click to Select
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Actions */}
        <div style={{
          marginTop: '1.5rem',
          display: 'flex',
          justifyContent: 'flex-end',
          alignItems: 'center',
          gap: '0.75rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.1)',
          paddingTop: '1.25rem'
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '8px 18px',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.08)',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              color: '#94a3b8',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            Cancel
          </button>
          <button
            onClick={() => handleGenerate(true)}
            disabled={isGenerating}
            style={{
              padding: '8px 22px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              border: 'none',
              color: '#ffffff',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: isGenerating ? 'wait' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)'
            }}
          >
            {isGenerating ? 'Generating Report...' : 'Generate & Open PDF Report'}
          </button>
        </div>

        {error && (
          <div style={{ marginTop: '1rem', padding: '0.65rem 1rem', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.35)', color: '#f87171', fontSize: '0.82rem' }}>
            {error}
          </div>
        )}
      </div>
    </div>
  )
}
