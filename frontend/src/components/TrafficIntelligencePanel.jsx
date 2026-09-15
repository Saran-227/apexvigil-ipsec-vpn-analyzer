import React from 'react'
import GlassCard from './GlassCard'
import { Cpu, Zap } from 'lucide-react'

export default function TrafficIntelligencePanel({ aiData }) {
  const tc = aiData?.traffic_classification || {}
  const op = aiData?.operational_mode || {}
  const kf = aiData?.key_flow_metrics || {}
  const fdr = aiData?.flow_dynamics_reconciliation

  const predProfile = tc.display_profile || tc.predicted_primary_profile || 'UNKNOWN'
  const confidence = (tc.confidence_score || 0) * 100
  const isConcurrent = tc.is_concurrent_traffic || false
  const activeApps = tc.active_applications || [predProfile]

  const mode = op.predicted_mode || 'UNKNOWN'
  const modeConf = (op.confidence_score || 0) * 100

  // Normalize rankedClasses to ensure classes and percentage scores render without NaN
  const rankedClasses = (() => {
    let raw = tc.ranked_classes
    if (!raw && tc.probability_distribution) {
      raw = Object.entries(tc.probability_distribution).map(([cls, prob]) => ({ class: cls, probability: prob }))
    }
    if (!Array.isArray(raw)) return []
    return raw.map((item, idx) => {
      let cName = ''
      let prob = 0
      if (Array.isArray(item)) {
        cName = item[0]
        prob = Number(item[1]) || 0
      } else if (item && typeof item === 'object') {
        cName = item.class || item.name || item.label || `Class ${idx + 1}`
        prob = item.probability !== undefined && !isNaN(Number(item.probability))
          ? Number(item.probability)
          : (item.score !== undefined ? Number(item.score) : 0)
      } else {
        cName = String(item)
      }
      return {
        class: String(cName).toUpperCase(),
        probability: Math.max(0, Math.min(1, prob))
      }
    }).sort((a, b) => b.probability - a.probability)
  })()

  return (
    <GlassCard className="traffic-intelligence-card">
      <div className="card-title-row">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className="icon-wrapper" style={{ width: 32, height: 32 }}>
            <Cpu size={16} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 700 }}>AI Encrypted Traffic Intelligence</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Statistical &amp; behavioral inference without decrypting ESP payloads
            </span>
          </div>
        </div>
        <span style={{
          fontSize: '0.72rem',
          fontWeight: 700,
          padding: '4px 10px',
          borderRadius: 'var(--radius-xs)',
          background: 'rgba(52, 211, 153, 0.15)',
          color: 'var(--accent-green)',
          border: '1px solid rgba(52, 211, 153, 0.3)',
          fontFamily: 'monospace'
        }}>
          LightGBM Champion (82.7%)
        </span>
      </div>

      {/* Dual Predictor Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
        gap: '0.75rem',
        marginTop: '1rem'
      }}>
        {/* Application Profile */}
        <div style={{
          padding: '1.1rem 1.25rem',
          background: 'var(--glass-inner)',
          border: '1px solid var(--glass-inner-border)',
          borderRadius: 'var(--radius-sm)'
        }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Predicted Application Profile
          </span>
          <div style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '4px' }}>
            {predProfile.toUpperCase()}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '6px' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--accent-blue)', fontWeight: 700 }}>
              {confidence.toFixed(1)}% Confidence
            </span>
            {isConcurrent && (
              <span style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'rgba(56, 189, 248, 0.15)',
                color: 'var(--accent-blue)',
                border: '1px solid rgba(56, 189, 248, 0.3)'
              }}>
                CONCURRENT MULTI-APP
              </span>
            )}
          </div>
        </div>

        {/* Operational Mode */}
        <div style={{
          padding: '1.1rem 1.25rem',
          background: 'var(--glass-inner)',
          border: '1px solid var(--glass-inner-border)',
          borderRadius: 'var(--radius-sm)'
        }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Operational Encapsulation Mode
          </span>
          <div style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '4px' }}>
            {mode.toUpperCase()}
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--accent-green)', fontWeight: 700, marginTop: '6px' }}>
            {modeConf.toFixed(1)}% Confidence (ExtraTrees Classifier)
          </div>
        </div>
      </div>

      {/* Multi-Class Probability Vector */}
      <div style={{ marginTop: '1.25rem' }}>
        <div style={{
          fontSize: '0.75rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--text-muted)',
          marginBottom: '0.75rem'
        }}>
          Multi-Class Probability Distribution ({rankedClasses.length || 8} Classes)
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
          {rankedClasses.map((item) => {
            const pct = (item.probability * 100).toFixed(1)
            const isTop = Number(pct) > 30
            return (
              <div key={item.class} style={{ display: 'grid', gridTemplateColumns: '80px 1fr 65px', alignItems: 'center', gap: '0.85rem' }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 700, color: isTop ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                  {item.class}
                </span>
                <div style={{
                  height: 7,
                  borderRadius: 4,
                  background: 'rgba(255, 255, 255, 0.08)',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    width: `${pct}%`,
                    height: '100%',
                    background: isTop ? 'var(--accent-blue)' : 'rgba(56, 189, 248, 0.45)',
                    borderRadius: 4,
                    transition: 'width 0.4s ease'
                  }} />
                </div>
                <span style={{ fontSize: '0.82rem', fontWeight: 700, color: isTop ? 'var(--accent-blue)' : 'var(--text-muted)', textAlign: 'right', fontFamily: 'monospace' }}>
                  {pct}%
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Flow Dynamics Grid (Pure Facts, Larger Numbers) */}
      <div style={{ marginTop: '1.25rem' }}>
        <div style={{
          fontSize: '0.75rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--text-muted)',
          marginBottom: '0.65rem'
        }}>
          Extracted Flow Dynamics (ESP Encrypted Data Plane)
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))',
          gap: '0.55rem'
        }}>
          {[
            { label: 'Mean Packet Size', val: `${Number(kf.mean_packet_length || 0).toFixed(1)} B` },
            { label: 'Size Dispersion', val: `± ${Number(kf.packet_length_std || 0).toFixed(1)} B` },
            { label: 'Mean IAT Pacing', val: `${Number(kf.mean_iat_ms || 0).toFixed(2)} ms` },
            { label: 'Burstiness Index', val: Number(kf.burstiness_index || 0).toFixed(2) },
            { label: 'Small Packets (<250B)', val: `${((kf.small_packet_ratio || 0) * 100).toFixed(1)}%` },
            { label: 'Large MTU (>900B)', val: `${((kf.large_packet_ratio || 0) * 100).toFixed(1)}%` }
          ].map((item, i) => (
            <div
              key={i}
              style={{
                padding: '0.75rem 0.85rem',
                background: 'var(--glass-inner)',
                border: '1px solid var(--glass-inner-border)',
                borderRadius: 'var(--radius-sm)',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{item.label}</span>
              <span style={{ fontSize: '1.02rem', fontWeight: 700, color: 'var(--text-primary)' }}>{item.val}</span>
            </div>
          ))}
        </div>
      </div>
    </GlassCard>
  )
}
