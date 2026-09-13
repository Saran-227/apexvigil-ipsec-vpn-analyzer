import { useState, useEffect, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import GlassSurface from './GlassSurface'

const NAV_ITEMS = [
  { label: 'HOME', href: '#top' },
  { label: 'TELEMETRY', href: '#traffic' },
  { label: 'VPN', href: '#vpn' },
  { label: 'EVENTS', href: '#events' },
  { label: 'TREND', href: '#trend' },
]

export default function Header() {
  const [active, setActive] = useState('#top')
  const location = useLocation()
  const navigate = useNavigate()
  const isAbout = location.pathname === '/about'
  const isManualScroll = useRef(false)
  const manualTimer = useRef(null)

  useEffect(() => {
    if (isAbout) return

    const handleScroll = () => {
      if (isManualScroll.current) return

      // If near top of page, home is active
      if (window.scrollY < 80) {
        setActive('#top')
        return
      }

      const scrollPos = window.scrollY + 140
      const ids = NAV_ITEMS.map(n => n.href.slice(1))

      for (let i = ids.length - 1; i >= 0; i--) {
        const el = document.getElementById(ids[i])
        if (el) {
          const rect = el.getBoundingClientRect()
          const top = rect.top + window.scrollY
          if (scrollPos >= top) {
            setActive(`#${ids[i]}`)
            break
          }
        }
      }
    }

    window.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()

    return () => {
      window.removeEventListener('scroll', handleScroll)
      clearTimeout(manualTimer.current)
    }
  }, [isAbout])

  const handleNav = (href) => {
    setActive(href)
    isManualScroll.current = true
    clearTimeout(manualTimer.current)
    manualTimer.current = setTimeout(() => {
      isManualScroll.current = false
    }, 850)

    if (isAbout) {
      navigate('/')
      setTimeout(() => {
        const el = document.querySelector(href)
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    } else {
      const el = document.querySelector(href)
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  return (
    <header className="topbar">
      <GlassSurface
        width="auto"
        height="auto"
        borderRadius={50}
        borderWidth={0.06}
        brightness={50}
        opacity={0.8}
        blur={0}
        backgroundOpacity={0}
        saturation={1.0}
        className="nav-glass-pill"
        style={{
          border: '1px solid rgba(255, 255, 255, 0.18)',
          boxShadow: '0 8px 24px rgba(0, 0, 0, 0.25)',
        }}
      >
        <nav className="nav-links p-[10px]" aria-label="Dashboard navigation">
          {NAV_ITEMS.map(({ label, href }) => (
            <button
              key={label}
              className={`nav-link${!isAbout && active === href ? ' active' : ''}`}
              onClick={() => handleNav(href)}
            >
              {label}
            </button>
          ))}
          <Link
            to="/about"
            className={`nav-link${isAbout ? ' active' : ''}`}
          >
            ABOUT
          </Link>
        </nav>
      </GlassSurface>
    </header>
  )
}
