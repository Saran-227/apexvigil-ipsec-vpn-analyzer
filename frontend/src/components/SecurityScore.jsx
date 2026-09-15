import React from 'react'

export default function SecurityScore({
  score = 100,
  rawScore,
  vetoCeiling,
  level = 'LOW',
  anomaly = false,
  postureLabel,
  complianceStatus
}) {
  const statusColor = (complianceStatus === 'PASS' || level === 'LOW')
    ? 'var(--accent-green)'
    : (complianceStatus === 'FAIL' || level === 'CRITICAL')
      ? 'var(--accent-red)'
      : 'var(--accent-amber)'

  const statusBg = (complianceStatus === 'PASS' || level === 'LOW')
    ? 'var(--green-soft)'
    : (complianceStatus === 'FAIL' || level === 'CRITICAL')
      ? 'var(--red-soft)'
      : 'var(--amber-soft)'

  const isCapped = vetoCeiling?.is_capped
  const statusText = complianceStatus || (score >= 85 ? 'PASS' : score < 60 ? 'FAIL' : 'WARNING')

  return (
    <div style={{
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      minHeight: '190px'
    }}>
      {/* Top row with standards kicker and status pill */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div className="section-kicker">NIST SP 800-77 REV. 1</div>
          <h3 style={{ margin: '2px 0 0', fontSize: '0.98rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            Cryptographic Risk Score
          </h3>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {isCapped && (
            <span style={{
              fontSize: '0.7rem',
              fontWeight: 700,
              padding: '3px 8px',
              borderRadius: '4px',
              background: 'rgba(239, 68, 68, 0.2)',
              color: 'var(--accent-red)',
              border: '1px solid rgba(239, 68, 68, 0.4)',
              letterSpacing: '0.04em'
            }} title={`Capped by Veto Ceiling from raw score ${rawScore}/100 due to fatal exploit`}>
              VETO CAP ({vetoCeiling.cap_limit})
            </span>
          )}
          <span style={{
            fontSize: '0.75rem',
            fontWeight: 800,
            padding: '3px 10px',
            borderRadius: '6px',
            background: statusBg,
            color: statusColor,
            border: `1px solid ${statusColor}44`,
            letterSpacing: '0.05em'
          }}>
            {statusText}
          </span>
        </div>
      </div>

      {/* Main Score Center Stage - Significantly Increased Size */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.75rem',
        margin: 'auto 0',
        padding: '0.85rem 0'
      }}>
        {/* Large Circular Gauge */}
        <div style={{
          width: 116,
          height: 116,
          borderRadius: '50%',
          border: `6px solid ${statusColor}`,
          boxShadow: `0 0 28px ${statusColor}33, inset 0 0 16px ${statusColor}22`,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          background: 'radial-gradient(circle, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.01) 70%)'
        }}>
          <strong style={{
            fontSize: '2.5rem',
            fontWeight: 900,
            lineHeight: 1,
            color: '#ffffff',
            letterSpacing: '-0.03em'
          }}>
            {score}
          </strong>
          <span style={{
            fontSize: '0.78rem',
            fontWeight: 700,
            color: 'var(--text-muted)',
            marginTop: 4
          }}>
            {isCapped ? `raw ${rawScore}` : '/ 100'}
          </span>
        </div>

        {/* Large Risk Level & Posture Narrative */}
        <div style={{ flex: 1 }}>
          <div style={{
            fontSize: '1.45rem',
            fontWeight: 800,
            margin: 0,
            color: statusColor,
            letterSpacing: '-0.01em',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            {level} RISK
          </div>
          <p style={{
            margin: '6px 0 0',
            fontSize: '0.88rem',
            fontWeight: 500,
            color: 'var(--text-secondary)',
            lineHeight: 1.45
          }}>
            {postureLabel || (anomaly ? 'Security anomaly detected in cryptographic negotiation' : 'Compliant IPsec cryptographic defense posture')}
          </p>
        </div>
      </div>

      {/* Bottom Status Bar matching the Active SPI row on the right */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0.6rem 0.85rem',
        background: 'var(--glass-inner)',
        borderRadius: 'var(--radius-xs)',
        border: '1px solid var(--border)'
      }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          Compliance Evaluation:
        </span>
        <span style={{ fontSize: '0.82rem', fontWeight: 700, color: statusColor }}>
          {statusText === 'PASS'
            ? 'RFC 4303 / RFC 7296 Compliant'
            : statusText === 'WARNING'
              ? 'Deprecated Suite Warning'
              : 'Critical Insecurity Detected'}
        </span>
      </div>
    </div>
  )
}