import React from 'react'
import GlassCard from './GlassCard'

export default function SecurityScore({ score = 100, rawScore, vetoCeiling, level = 'LOW', anomaly = false, postureLabel, complianceStatus }) {
  const statusColor = (complianceStatus === 'PASS' || level === 'LOW')
    ? 'var(--accent-green)'
    : (complianceStatus === 'FAIL' || level === 'CRITICAL')
      ? 'var(--accent-red)'
      : 'var(--accent-amber)'

  const isCapped = vetoCeiling?.is_capped

  return (
    <GlassCard className="score-card" style={{ padding: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.65rem' }}>
        <div className="section-kicker">NIST SP 800-77 REV. 1</div>
        <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
          {isCapped && (
            <span style={{
              fontSize: '0.65rem',
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: '4px',
              background: 'rgba(239, 68, 68, 0.2)',
              color: 'var(--accent-red)',
              border: '1px solid rgba(239, 68, 68, 0.4)'
            }} title={`Capped by Veto Ceiling from raw score ${rawScore}/100 due to fatal exploit`}>
              VETO CAP ({vetoCeiling.cap_limit})
            </span>
          )}
          <span style={{
            fontSize: '0.68rem',
            fontWeight: 700,
            padding: '2px 8px',
            borderRadius: '4px',
            background: complianceStatus === 'PASS' ? 'var(--green-soft)' : complianceStatus === 'FAIL' ? 'var(--red-soft)' : 'var(--amber-soft)',
            color: statusColor
          }}>
            {complianceStatus || (score >= 85 ? 'PASS' : score < 60 ? 'FAIL' : 'WARNING')}
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        <div style={{
          width: 76,
          height: 76,
          borderRadius: '50%',
          border: `4px solid ${statusColor}`,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          background: 'var(--glass-inner)'
        }}>
          <strong style={{ fontSize: '1.35rem', fontWeight: 800, lineHeight: 1, color: 'var(--text-primary)' }}>
            {score}
          </strong>
          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
            {isCapped ? `raw ${rawScore}` : '/ 100'}
          </span>
        </div>

        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0, color: statusColor }}>
            {level} RISK
          </h2>
          <p style={{ margin: '3px 0 0', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.35 }}>
            {postureLabel || (anomaly ? 'Security anomaly detected' : 'Compliant defense posture')}
          </p>
        </div>
      </div>
    </GlassCard>
  )
}