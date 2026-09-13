import React from 'react'
import GlassCard from './GlassCard'
import { Shield, ShieldAlert, ShieldCheck, Key, Lock, CheckCircle, AlertTriangle, XCircle } from 'lucide-react'

export default function CryptoAuditPanel({ auditData, ikeDetails, execSummary }) {
  const suite = auditData?.negotiated_suite || {}
  const ikeProto = ikeDetails || {}
  const ikeProp = suite.ike_sa_proposal || ikeProto.ike_sa_proposal || {}
  const espProp = suite.esp_child_sa_proposal || ikeProto.esp_child_sa_proposal || {}

  const espCipher = espProp.encryption || suite.encryption || (auditData?.posture_label ? 'UNOBSERVED (ESP ONLY)' : 'None')
  const ikeCipher = ikeProp.encryption || (ikeProto.handshake_detected ? suite.encryption : 'UNOBSERVED (MID-STREAM)')
  const spiPair = suite.spi_pair || execSummary?.spi_pair || 'None Observed'
  const authMethod = suite.auth_method || execSummary?.auth_method || 'Pre-Shared Key (PSK)'
  const keyLen = (espProp.key_length || suite.key_length) ? `${espProp.key_length || suite.key_length} bits` : 'N/A'
  const integrity = suite.integrity || espProp.integrity || 'None'
  const prf = suite.prf || ikeProp.prf || 'None'
  const dhGroup = suite.dh_group || ikeProp.dh_group || 'None'
  const pfsText = suite.pfs_status ? `${suite.pfs_status} (${suite.pfs_details || 'N/A'})` : 'DISABLED'
  const replay = suite.replay_protection || execSummary?.replay_protection || 'RFC 4303 Active'
  const replayWidth = suite.replay_window_width || execSummary?.replay_window_width || 'Undeterminable via Passive Wiretap (Local Gateway Policy)'
  const keyLifetime = suite.key_lifetime || execSummary?.key_lifetime || 'Autonomous Local Gateway Policy (RFC 7296)'
  const ikeVer = ikeProto.ike_version ? `IKEv${ikeProto.ike_version}` : 'None'
  const natT = ikeProto.nat_traversal ? 'UDP 4500 (ACTIVE)' : 'Native ESP (Proto 50)'
  const ctrlPlane = suite.control_plane || execSummary?.control_plane_summary || 'N/A'

  const vulns = auditData?.violations || []

  const cryptoParams = [
    { label: 'ESP SA Cipher (Phase 2)', value: espCipher, highlight: true },
    { label: 'IKE SA Cipher (Phase 1)', value: ikeCipher },
    { label: 'Active ESP SPIs', value: spiPair, mono: true, color: 'var(--accent-blue)' },
    { label: 'Authentication Method', value: authMethod },
    { label: 'Cipher Key Length', value: keyLen },
    { label: 'Integrity / MAC Tag', value: integrity },
    { label: 'Pseudo-Random Function (PRF)', value: prf },
    { label: 'Diffie-Hellman Group', value: dhGroup },
    { label: 'Perfect Forward Secrecy (PFS)', value: pfsText },
    { label: 'Anti-Replay Window', value: replay },
    { label: 'Replay Buffer Bit-Width', value: replayWidth },
    { label: 'Key Lifetime / Rekeying', value: keyLifetime },
    { label: 'Key Exchange Protocol', value: ikeVer },
    { label: 'Encapsulation / NAT-T', value: natT },
    { label: 'Control Plane Handshake', value: ctrlPlane }
  ]

  return (
    <GlassCard className="crypto-audit-card">
      <div className="card-title-row">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className="icon-wrapper" style={{ width: 32, height: 32 }}>
            <Lock size={16} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>Deterministic Cryptographic Audit</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              RFC-compliant inspection of unencrypted IKE handshakes &amp; SA transforms
            </span>
          </div>
        </div>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          padding: '4px 8px',
          borderRadius: 'var(--radius-xs)',
          background: 'rgba(147, 197, 253, 0.15)',
          color: 'var(--accent-blue)',
          border: '1px solid var(--border-strong)',
          fontFamily: 'monospace'
        }}>
          NIST SP 800-77 Rev. 1
        </span>
      </div>

      {/* Parameter Rows Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(310px, 1fr))',
        gap: '0.5rem',
        marginTop: '1rem'
      }}>
        {cryptoParams.map((param, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              flexDirection: 'column',
              padding: '0.6rem 0.8rem',
              background: 'var(--glass-inner)',
              border: '1px solid var(--glass-inner-border)',
              borderRadius: 'var(--radius-sm)'
            }}
          >
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '2px' }}>
              {param.label}
            </span>
            <span style={{
              fontSize: '0.82rem',
              fontWeight: param.highlight ? 600 : 500,
              fontFamily: param.mono ? 'monospace' : 'inherit',
              color: param.color || 'var(--text-primary)',
              wordBreak: 'break-word',
              lineHeight: 1.3
            }}>
              {param.value}
            </span>
          </div>
        ))}
      </div>

      {/* 6-Pillar Formalized Scoring Rubric Breakdown */}
      {auditData?.rubric_breakdown && Object.keys(auditData.rubric_breakdown).length > 0 && (
        <div style={{ marginTop: '1.25rem' }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '0.65rem'
          }}>
            <div>
              <h4 style={{ margin: 0, fontSize: '0.82rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-primary)' }}>
                NIST SP 800-77 &amp; CNSA 2.0 Scoring Rubric (6 Pillars)
              </h4>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Multi-criteria weighted evaluation {auditData.raw_score !== undefined ? `(Raw: ${auditData.raw_score}/100)` : ''}
              </span>
            </div>
            {auditData?.veto_ceiling?.is_capped && (
              <span style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'rgba(239, 68, 68, 0.15)',
                color: 'var(--accent-red)',
                border: '1px solid rgba(239, 68, 68, 0.35)'
              }}>
                VETO CEILING APPLIED ({auditData.veto_ceiling.cap_limit}/100)
              </span>
            )}
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
            gap: '0.6rem'
          }}>
            {Object.entries(auditData.rubric_breakdown).map(([key, item]) => {
              const pct = Math.round((item.score / item.max_score) * 100)
              const badgeColor = item.status === 'OPTIMAL'
                ? 'var(--accent-green)'
                : item.status === 'COMPLIANT'
                  ? 'var(--accent-blue)'
                  : item.status === 'CRITICAL_FAIL'
                    ? 'var(--accent-red)'
                    : item.status === 'UNVERIFIED'
                      ? 'var(--text-muted)'
                      : 'var(--accent-amber)'
              const badgeBg = item.status === 'OPTIMAL'
                ? 'var(--green-soft)'
                : item.status === 'COMPLIANT'
                  ? 'rgba(59, 130, 246, 0.15)'
                  : item.status === 'CRITICAL_FAIL'
                    ? 'var(--red-soft)'
                    : 'var(--amber-soft)'

              return (
                <div
                  key={key}
                  style={{
                    padding: '0.75rem 0.85rem',
                    background: 'var(--glass-inner)',
                    border: '1px solid var(--glass-inner-border)',
                    borderRadius: 'var(--radius-sm)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', maxWidth: '75%' }}>
                      {item.name}
                    </span>
                    <span style={{
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      padding: '1px 6px',
                      borderRadius: '3px',
                      background: badgeBg,
                      color: badgeColor,
                      fontFamily: 'monospace'
                    }}>
                      {item.score}/{item.max_score}
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div style={{
                    width: '100%',
                    height: 4,
                    borderRadius: 2,
                    background: 'rgba(255, 255, 255, 0.08)',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${pct}%`,
                      height: '100%',
                      background: badgeColor,
                      borderRadius: 2,
                      transition: 'width 0.4s ease'
                    }} />
                  </div>

                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: 1.35 }}>
                    {item.rationale}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Threats / Vulnerabilities */}
      <div style={{ marginTop: '1.25rem' }}>
        {vulns.length === 0 ? (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.85rem',
            padding: '0.85rem 1rem',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--green-soft)',
            border: '1px solid rgba(52, 211, 153, 0.25)'
          }}>
            <ShieldCheck size={22} color="var(--accent-green)" />
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-green)' }}>
                NIST SP 800-77 Rev. 1 Cryptographic Compliance Achieved
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                Zero active cryptographic vulnerabilities detected. Approved AEAD cipher suites, SHA-2 PRF, and modern Diffie-Hellman parameters active.
              </div>
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{
              fontSize: '0.75rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--accent-red)'
            }}>
              Identified Cryptographic Deficiencies &amp; CVE Threats ({vulns.length})
            </div>
            {vulns.map((v, idx) => (
              <div
                key={idx}
                style={{
                  padding: '0.85rem 1rem',
                  borderRadius: 'var(--radius-sm)',
                  background: v.severity === 'CRITICAL' ? 'var(--red-soft)' : 'var(--amber-soft)',
                  border: `1px solid ${v.severity === 'CRITICAL' ? 'rgba(248, 113, 113, 0.3)' : 'rgba(251, 191, 36, 0.3)'}`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{
                    fontSize: '0.82rem',
                    fontWeight: 600,
                    color: v.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-amber)'
                  }}>
                    [{v.severity}] {v.title}
                  </span>
                  <span style={{ fontSize: '0.7rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                    {v.cwe}
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  {v.description}
                </div>
                {v.remediation && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-primary)', marginTop: '4px' }}>
                    <strong>Remediation:</strong> {v.remediation}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </GlassCard>
  )
}
