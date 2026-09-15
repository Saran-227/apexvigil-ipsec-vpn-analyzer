import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Radio, ArrowLeft } from 'lucide-react'
import logoIcon from '../public/icon.png'

const NAV_ITEMS = [
  { label: 'INGESTION', href: '#ingestion' },
  { label: 'SECURITY SCORE', href: '#security' },
  { label: 'CRYPTO AUDIT', href: '#audit' },
  { label: 'AI TELEMETRY', href: '#ai-telemetry' },
  { label: 'TIMELINE', href: '#timeline' },
]

export default function Header({ connection = 'LIVE' }) {
  const navigate = useNavigate()
  const [active, setActive] = useState('#ingestion')

  useEffect(() => {
    const ids = NAV_ITEMS.map(n => n.href.slice(1))
    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(e => {
          if (e.isIntersecting) setActive(`#${e.target.id}`)
        })
      },
      { rootMargin: '-60px 0px -60% 0px', threshold: 0 }
    )
    ids.forEach(id => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [])

  const handleNav = (href) => {
    const el = document.querySelector(href)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <header className="topbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <button
          onClick={() => navigate('/')}
          className="header-hub-btn"
          title="Return to Workspace Hub mode selector"
        >
          <ArrowLeft size={14} />
          <span>Hub</span>
        </button>
        <div className="topbar-divider" />
        <div className="brand" onClick={() => handleNav('#ingestion')} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              backgroundColor: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 2,
              overflow: 'hidden',
              flexShrink: 0
            }}
          >
            <img
              src={logoIcon}
              alt="ApexVigil Logo"
              style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }}
            />
          </div>
          <div>
            <div className="brand-title">ApexVigil <em>IPsec Intelligence</em></div>
            <div className="brand-sub">Forensic PCAP Workspace</div>
          </div>
        </div>
      </div>

      <nav className="nav-links" aria-label="Dashboard navigation">
        {NAV_ITEMS.map(({ label, href }) => (
          <button
            key={label}
            className={`nav-link${active === href ? ' active' : ''}`}
            onClick={() => handleNav(href)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="top-actions">
        <button
          onClick={() => navigate('/realtime')}
          className="header-mode-switch-btn"
          title="Switch to Real-Time Live Stream Cockpit"
        >
          <Radio size={13} color="var(--accent-cyan)" />
          <span>Real-Time Mode</span>
        </button>
      </div>
    </header>
  )
}
