import logoIcon from '../public/icon.png'
import { API_BASE } from '../services/api'
import React, { useState, useEffect, useRef, useMemo } from 'react'
import ReportExportModal from '../components/ReportExportModal'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  FileText,
  Radio,
  ArrowLeft,
  FileCode,
  ShieldCheck,
  Shield,
  Activity,
  Play,
  Square,
  RotateCcw,
  Wifi,
  Layers,
  Cpu,
  Lock,
  Clock,
  AlertTriangle,
  Info,
  Plus,
  Trash2,
  Sliders,
  Settings,
  ShieldAlert,
  ChevronRight,
  ChevronDown,
  CheckCircle,
  XCircle,
  BarChart2,
  RefreshCw,
  PhoneCall,
  Video,
  Globe,
  MessageSquare,
  Mail,
  Package,
  Network
} from 'lucide-react'
import GlassCard from '../components/GlassCard'

const TRAFFIC_ICONS = {
  voip: PhoneCall,
  video: Video,
  web: Globe,
  chat: MessageSquare,
  email: Mail,
  bulk: Package,
  icmp: Radio,
  mixed: Network
}

const CIPHER_OPTIONS = [
  { value: 'AES-256-GCM', label: 'AES-256-GCM', klen: 256, isAead: true },
  { value: 'AES-128-GCM', label: 'AES-128-GCM', klen: 128, isAead: true },
  { value: 'AES-256-CBC', label: 'AES-256-CBC', klen: 256, isAead: false },
  { value: 'AES-128-CBC', label: 'AES-128-CBC', klen: 128, isAead: false },
  { value: '3DES-CBC', label: '3DES-CBC', klen: 192, isAead: false, isBad: true },
  { value: 'DES', label: 'DES', klen: 64, isAead: false, isBad: true }
]

const DH_OPTIONS = [
  { num: 19, name: 'Group 19 (ECP-256)', label: 'Group 19 (ECP-256)' },
  { num: 20, name: 'Group 20 (ECP-384)', label: 'Group 20 (ECP-384)' },
  { num: 14, name: 'Group 14 (MODP 2048)', label: 'Group 14 (MODP 2048)' },
  { num: 5, name: 'Group 5 (MODP 1536)', label: 'Group 5 (MODP 1536)' },
  { num: 2, name: 'Group 2 (MODP 1024)', label: 'Group 2 (MODP 1024)', isBad: true },
  { num: 1, name: 'Group 1 (MODP 768)', label: 'Group 1 (MODP 768)', isBad: true }
]

const INTEGRITY_OPTIONS = [
  { value: 'AEAD Combined (GCM Tag)', label: 'AEAD (128-bit Tag)' },
  { value: 'HMAC-SHA-384', label: 'HMAC-SHA-384' },
  { value: 'HMAC-SHA-256', label: 'HMAC-SHA-256' },
  { value: 'HMAC-SHA-1', label: 'HMAC-SHA-1' },
  { value: 'HMAC-MD5', label: 'HMAC-MD5', isBad: true }
]


const TRAFFIC_PROFILES = [
  { key: 'voip', name: 'VoIP' },
  { key: 'video', name: 'Video Streaming' },
  { key: 'web', name: 'Web Browsing' },
  { key: 'chat', name: 'Secure Chat' },
  { key: 'email', name: 'E-Mail' },
  { key: 'bulk', name: 'Bulk Transfer' },
  { key: 'icmp', name: 'ICMP Echo' },
  { key: 'mixed', name: 'Concurrent Multiplexed' }
]

const TRAFFIC_STATS = {
  voip: { pps_range: [45, 55], mean_packet_size: 180 },
  video: { pps_range: [80, 160], mean_packet_size: 1150 },
  web: { pps_range: [25, 60], mean_packet_size: 650 },
  chat: { pps_range: [5, 20], mean_packet_size: 160 },
  email: { pps_range: [15, 35], mean_packet_size: 450 },
  bulk: { pps_range: [100, 200], mean_packet_size: 1420 },
  icmp: { pps_range: [1, 5], mean_packet_size: 98 },
  mixed: { pps_range: [70, 130], mean_packet_size: 800 }
}

const PRESET_TOPOLOGIES = {
  tactical: {
    name: 'Tactical Military Defense Mesh (3 Links)',
    desc: 'HQ-to-DC (Secure AEAD), Tactical Edge (Degraded link), and Cloud VPN.',
    links: [
      {
        id: 'link-1',
        name: 'Link 1: HQ Gateway <-> Datacenter Core',
        source: '172.28.0.2',
        destination: '172.28.0.3',
        operating_mode: 'tunnel',
        crypto: {
          ike_version: 2,
          encryption: 'AES-256-GCM',
          key_length: 256,
          dh_group: 'Group 19 (ECP-256)',
          dh_group_num: 19,
          integrity: 'AEAD Combined (GCM Tag)',
          prf: 'PRF_HMAC_SHA2_256',
          pfs_enabled: true
        },
        traffic: 'voip',
        degradation: { jitter_ms: 4, packet_loss_pct: 0.2, reorder_pct: 0.0, mtu: 1500 }
      },
      {
        id: 'link-2',
        name: 'Link 2: Tactical Edge <-> Command HQ',
        source: '10.0.10.5',
        destination: '172.28.0.2',
        operating_mode: 'tunnel',
        crypto: {
          ike_version: 1,
          encryption: '3DES-CBC',
          key_length: 192,
          dh_group: 'Group 2 (MODP 1024)',
          dh_group_num: 2,
          integrity: 'HMAC-SHA-1',
          prf: 'PRF_HMAC_SHA1',
          pfs_enabled: true
        },
        traffic: 'chat',
        degradation: { jitter_ms: 35, packet_loss_pct: 4.5, reorder_pct: 2.0, mtu: 1500 }
      },
      {
        id: 'link-3',
        name: 'Link 3: Field Recon <-> Mission Hub',
        source: '192.168.10.12',
        destination: '10.200.0.1',
        operating_mode: 'transport',
        crypto: {
          ike_version: 2,
          encryption: 'AES-128-CBC',
          key_length: 128,
          dh_group: 'Group 14 (MODP 2048)',
          dh_group_num: 14,
          integrity: 'HMAC-SHA-256',
          prf: 'PRF_HMAC_SHA2_256',
          pfs_enabled: false
        },
        traffic: 'video',
        degradation: { jitter_ms: 15, packet_loss_pct: 1.2, reorder_pct: 0.5, mtu: 1500 }
      }
    ]
  },
  zerotrust: {
    name: 'Zero-Trust Secure Backbone (2 Links)',
    desc: 'Pure NSA CNSA 2.0 compliant AES-256-GCM tunnels with Group 19/20 and active PFS.',
    links: [
      {
        id: 'link-1',
        name: 'Link 1: Primary Backbone Alpha',
        source: '10.100.1.1',
        destination: '10.100.2.1',
        operating_mode: 'tunnel',
        crypto: {
          ike_version: 2,
          encryption: 'AES-256-GCM',
          key_length: 256,
          dh_group: 'Group 19 (ECP-256)',
          dh_group_num: 19,
          integrity: 'AEAD Combined (GCM Tag)',
          prf: 'PRF_HMAC_SHA2_256',
          pfs_enabled: true
        },
        traffic: 'mixed',
        degradation: { jitter_ms: 2, packet_loss_pct: 0.0, reorder_pct: 0.0, mtu: 1500 }
      },
      {
        id: 'link-2',
        name: 'Link 2: Classified Enclave Sync',
        source: '10.200.5.1',
        destination: '10.200.5.2',
        operating_mode: 'tunnel',
        crypto: {
          ike_version: 2,
          encryption: 'AES-256-GCM',
          key_length: 256,
          dh_group: 'Group 20 (ECP-384)',
          dh_group_num: 20,
          integrity: 'AEAD Combined (GCM Tag)',
          prf: 'PRF_HMAC_SHA2_384',
          pfs_enabled: true
        },
        traffic: 'bulk',
        degradation: { jitter_ms: 1, packet_loss_pct: 0.0, reorder_pct: 0.0, mtu: 1500 }
      }
    ]
  },
  legacy: {
    name: 'Vulnerable Legacy Infiltration (2 Links)',
    desc: 'Sweet32 3DES and Logjam DH Group 2 tunnels for vulnerability testing.',
    links: [
      {
        id: 'link-1',
        name: 'Link 1: Legacy SCADA Link (Sweet32 Vulnerable)',
        source: '192.168.99.10',
        destination: '192.168.99.1',
        operating_mode: 'tunnel',
        crypto: {
          ike_version: 1,
          encryption: '3DES-CBC',
          key_length: 192,
          dh_group: 'Group 2 (MODP 1024)',
          dh_group_num: 2,
          integrity: 'HMAC-SHA-1',
          prf: 'PRF_HMAC_SHA1',
          pfs_enabled: true
        },
        traffic: 'icmp',
        degradation: { jitter_ms: 20, packet_loss_pct: 2.0, reorder_pct: 1.0, mtu: 1500 }
      },
      {
        id: 'link-2',
        name: 'Link 2: Unhardened Field Office (Broken MD5)',
        source: '10.10.10.2',
        destination: '172.28.0.2',
        operating_mode: 'transport',
        crypto: {
          ike_version: 1,
          encryption: 'AES-128-CBC',
          key_length: 128,
          dh_group: 'Group 1 (MODP 768)',
          dh_group_num: 1,
          integrity: 'HMAC-MD5',
          prf: 'PRF_HMAC_MD5',
          pfs_enabled: false
        },
        traffic: 'web',
        degradation: { jitter_ms: 18, packet_loss_pct: 3.5, reorder_pct: 0.5, mtu: 1500 }
      }
    ]
  }
}

export default function RealtimeCockpit({ connection = 'LIVE' }) {
  const navigate = useNavigate()
  const location = useLocation()
  const getInitialTab = () => {
    const params = new URLSearchParams(location.search)
    if (params.get('tab')) return params.get('tab')
    if (location.state && location.state.tab) return location.state.tab
    return 'config'
  }
  const [activeTab, setActiveTab] = useState(getInitialTab)

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const tab = params.get('tab') || (location.state && location.state.tab)
    if (tab && (tab === 'config' || tab === 'results')) {
      setActiveTab(tab)
    }
  }, [location.search, location.state])
  const [links, setLinks] = useState(PRESET_TOPOLOGIES.tactical.links)
  const [selectedLinkIndex, setSelectedLinkIndex] = useState(0)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simulationResults, setSimulationResults] = useState(null)
  const [inspectedLink, setInspectedLink] = useState(null)
  const [errorMsg, setErrorMsg] = useState(null)
  const [isStreaming, setIsStreaming] = useState(false)
  const [isAborted, setIsAborted] = useState(false)
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const [streamHistory, setStreamHistory] = useState([])
  const [isReportModalOpen, setIsReportModalOpen] = useState(false)
  const streamIntervalRef = useRef(null)

  const formatElapsed = (totalSec) => {
    const m = Math.floor(totalSec / 60).toString().padStart(2, '0')
    const s = (totalSec % 60).toString().padStart(2, '0')
    return `${m}:${s}`
  }

  const startLiveTicker = () => {
    if (streamIntervalRef.current) clearInterval(streamIntervalRef.current)
    setIsStreaming(true)
    setIsAborted(false)

    streamIntervalRef.current = setInterval(() => {
      try {
        setElapsedSeconds(prev => prev + 1)

        setSimulationResults(prevResults => {
        if (!prevResults || !prevResults.links) return prevResults

        let secTotalPackets = 0
        let secTotalBytes = 0

        const updatedLinks = prevResults.links.map(lnk => {
          const tKey = (lnk.traffic_key || lnk.traffic || 'voip').toLowerCase()
          const tInfo = TRAFFIC_STATS[tKey] || TRAFFIC_STATS.voip
          const [minPps, maxPps] = tInfo.pps_range || [40, 60]
          const meanSize = tInfo.mean_packet_size || 180
          const lossPct = (lnk.channel_conditions?.packet_loss_pct || 0) / 100

          // Calculate random live PPS slice
          const noise = 0.85 + Math.random() * 0.3
          const basePps = Math.round(((minPps + maxPps) / 2) * noise)
          
          const drops = (Math.random() < lossPct || lossPct > 0.03) ? Math.max(1, Math.round(basePps * lossPct)) : 0
          const delivered = Math.max(1, basePps - drops)
          const bytesThisSec = delivered * meanSize

          secTotalPackets += delivered
          secTotalBytes += bytesThisSec

          const prevTel = lnk.stream_telemetry || {}
          const newTotal = (prevTel.total_packets || 0) + delivered + drops
          const newEsp = (prevTel.esp_packets || 0) + delivered
          const newDrops = (prevTel.dropped_packets || 0) + drops
          const liveKbps = Math.round((bytesThisSec * 8) / 1000)

          const baseJitter = lnk.channel_conditions?.jitter_ms || 0
          const liveJitter = Math.max(0, Math.round((baseJitter + (Math.random() * 4 - 2)) * 10) / 10)

          return {
            ...lnk,
            live_pps: delivered,
            live_jitter_ms: liveJitter,
            stream_telemetry: {
              ...prevTel,
              total_packets: newTotal,
              esp_packets: newEsp,
              dropped_packets: newDrops,
              throughput_kbps: liveKbps,
              live_jitter_ms: liveJitter,
              current_seq: (prevTel.current_seq || 1000) + delivered
            }
          }
        })

        // Update rolling streamHistory for oscilloscope
        setStreamHistory(prevHist => [...prevHist, secTotalPackets])

        const prevSummary = prevResults.network_summary || {}
        const updatedSummary = {
          ...prevSummary,
          total_packets_streamed: (prevSummary.total_packets_streamed || 0) + secTotalPackets,
          total_data_volume_mb: Math.round(((prevSummary.total_data_volume_mb || 0) + (secTotalBytes / (1024 * 1024))) * 100) / 100,
          current_aggregate_pps: secTotalPackets
        }

        // Keep active inspected link updated
        setInspectedLink(currentInspected => {
          if (!currentInspected) return updatedLinks[0]
          return updatedLinks.find(l => l.id === currentInspected.id) || updatedLinks[0]
        })

        return {
          ...prevResults,
          links: updatedLinks,
          network_summary: updatedSummary
        }
      })
      } catch (err) {
        console.error('[LiveTicker Error]:', err)
      }
    }, 1000)
  }

  const handleAbortStream = () => {
    if (streamIntervalRef.current) {
      clearInterval(streamIntervalRef.current)
      streamIntervalRef.current = null
    }
    setIsStreaming(false)
    setIsAborted(true)
  }

  const handleResumeStream = () => {
    startLiveTicker()
  }

  const handleResetStream = () => {
    if (streamIntervalRef.current) {
      clearInterval(streamIntervalRef.current)
      streamIntervalRef.current = null
    }
    setIsStreaming(false)
    setIsAborted(false)
    setElapsedSeconds(0)
    setStreamHistory([])
    handleRunSimulation(links, false)
  }

  useEffect(() => {
    return () => {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current)
      }
    }
  }, [])

  // Load default preset on initial mount without switching away from Topology & Config
  useEffect(() => {
    const targetTab = new URLSearchParams(location.search).get('tab') || (location.state && location.state.tab) || 'config'
    const shouldSwitch = targetTab === 'results'
    handleRunSimulation(PRESET_TOPOLOGIES.tactical.links, shouldSwitch)
  }, [])

  const handleApplyPreset = (presetKey) => {
    const preset = PRESET_TOPOLOGIES[presetKey]
    if (preset) {
      setLinks(preset.links)
      setSelectedLinkIndex(0)
      handleRunSimulation(preset.links, false)
    }
  }

  const handleAddLink = () => {
    const newIdx = links.length + 1
    const newLink = {
      id: `link-${Date.now().toString().slice(-4)}`,
      name: `Link ${newIdx}: New Operational Tunnel`,
      source: `172.28.0.${newIdx + 1}`,
      destination: '172.28.0.2 (Gateway)',
      operating_mode: 'tunnel',
      crypto: {
        ike_version: 2,
        encryption: 'AES-256-GCM',
        key_length: 256,
        dh_group: 'Group 19 (ECP-256)',
        dh_group_num: 19,
        integrity: 'AEAD Combined (GCM Tag)',
        prf: 'PRF_HMAC_SHA2_256',
        pfs_enabled: true
      },
      traffic: 'voip',
      degradation: { jitter_ms: 5, packet_loss_pct: 0.5, reorder_pct: 0.0, mtu: 1500 }
    }
    setLinks([...links, newLink])
    setSelectedLinkIndex(links.length)
  }

  const handleRemoveLink = (index) => {
    if (links.length <= 1) return
    const updated = links.filter((_, i) => i !== index)
    setLinks(updated)
    setSelectedLinkIndex(Math.max(0, index - 1))
  }

  const updateSelectedLink = (path, value) => {
    const updated = [...links]
    const cur = { ...updated[selectedLinkIndex] }

    if (path.startsWith('crypto.')) {
      const field = path.split('.')[1]
      cur.crypto = { ...cur.crypto, [field]: value }
    } else if (path.startsWith('degradation.')) {
      const field = path.split('.')[1]
      cur.degradation = { ...cur.degradation, [field]: value }
    } else {
      cur[path] = value
    }

    updated[selectedLinkIndex] = cur
    setLinks(updated)
  }

  const handleRunSimulation = async (linksToRun = links, switchTab = true) => {
    setIsSimulating(true)
    setErrorMsg(null)
    try {
      const resp = await fetch(API_BASE + '/simulate/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ links: linksToRun })
      })
      if (!resp.ok) {
        throw new Error(`Simulation request returned HTTP ${resp.status}`)
      }
      const data = await resp.json()
      setSimulationResults(data)
      if (data.links && data.links.length > 0) {
        setInspectedLink(data.links[0])
      }
      const initPps = data.network_summary?.current_aggregate_pps || (data.oscilloscope?.aggregate_pps?.[0] || 180)
      setStreamHistory([initPps])
      setElapsedSeconds(0)
      if (switchTab) {
        setActiveTab('results')
        startLiveTicker()
      }
    } catch (err) {
      console.error('Simulation error:', err)
      setErrorMsg(err.message)
    } finally {
      setIsSimulating(false)
    }
  }

  const WINDOW_SECONDS = 15
  const graphData = useMemo(() => {
    const hist = streamHistory.length > 0 ? streamHistory : [180]
    let displayed = []

    if (elapsedSeconds <= WINDOW_SECONDS) {
      // 0 to 15s: Graph starts from the beginning (x=0) and moves towards the end
      displayed = hist.slice(0, elapsedSeconds + 1)
    } else {
      // > 15s: 15s window keeps moving ahead, pointer stays at the end and graph moves leftward
      displayed = hist.slice(-(WINDOW_SECONDS + 1))
    }

    const maxPps = Math.max(...displayed, 220)
    const minPps = 0

    const points = displayed.map((pps, idx) => {
      let x = (idx / WINDOW_SECONDS) * 500
      const y = 58 - ((pps - minPps) / (maxPps - minPps || 1)) * 48
      return { x: Math.min(500, Math.max(0, x)), y: Math.min(65, Math.max(8, y)), pps }
    })

    const leadPoint = points[points.length - 1] || { x: 0, y: 30, pps: 0 }
    const leadX = leadPoint.x
    const leadY = leadPoint.y

    let linePath = ''
    let areaPath = ''
    if (points.length <= 1) {
      linePath = `M 0 ${leadY.toFixed(1)} L 0 ${leadY.toFixed(1)}`
      areaPath = `M 0 65 L 0 ${leadY.toFixed(1)} L 0 65 Z`
    } else {
      linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
      areaPath = `M 0 65 ` + points.map(p => `L ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ') + ` L ${leadX.toFixed(1)} 65 Z`
    }

    return {
      points,
      areaPath,
      linePath,
      leadX,
      leadY,
      currentPps: leadPoint.pps || 0
    }
  }, [streamHistory, elapsedSeconds])

  const curLink = links[selectedLinkIndex] || links[0]

  return (
    <div className="cockpit-container">
      {/* Topbar with Mode Navigation */}
      <header className="cockpit-topbar">
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button
            className="cockpit-back-btn"
            onClick={() => navigate('/')}
            title="Return to Workspace Hub mode selector"
          >
            <ArrowLeft size={16} />
            <span>Workspace Hub</span>
          </button>
          <div className="cockpit-divider" />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
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
              <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                ApexVigil <em>IPsec Live Cockpit</em>
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                Real-Time Multi-Link Stream Wiretap &amp; Telemetry
              </div>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {/* View Switcher Tabs */}
          <div className="cockpit-tabs">
            <button
              className={`cockpit-tab-btn ${activeTab === 'config' ? 'active' : ''}`}
              onClick={() => setActiveTab('config')}
            >
              <Sliders size={13} />
              <span>1. Topology &amp; Link Config</span>
            </button>
            <button
              className={`cockpit-tab-btn ${activeTab === 'results' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('results')
                if (!isStreaming && !isAborted) {
                  startLiveTicker()
                }
              }}
            >
              <BarChart2 size={13} />
              <span>2. Live Stream Results ({simulationResults?.links?.length || links.length} Links)</span>
            </button>
          </div>

          <div className="cockpit-divider" />

          <button
            className="switch-mode-btn"
            onClick={() => navigate('/pcap')}
          >
            <FileCode size={14} />
            <span>Switch to PCAP Forensics</span>
          </button>
        </div>
      </header>

      {/* Main Cockpit Body */}
      <main className="cockpit-main">
        {/* Error Banner */}
        {errorMsg && (
          <div style={{
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--red-soft)',
            border: '1px solid var(--accent-red)',
            color: 'var(--accent-red)',
            fontSize: '0.82rem',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <AlertTriangle size={16} />
            <span>Simulation error: {errorMsg}</span>
          </div>
        )}

        {/* VIEW 1: TOPOLOGY & CONFIGURATION BUILDER */}
        {activeTab === 'config' && (
          <div>
            {/* Top Command Strip: Presets & Action */}
            <GlassCard style={{ padding: '0.85rem 1.25rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>
                    LOAD TOPOLOGY PRESET:
                  </span>
                  <button
                    className="preset-chip"
                    onClick={() => handleApplyPreset('tactical')}
                  >
                    <Shield size={14} color="#38bdf8" /> <span>Tactical Military Mesh (3 Links)</span>
                  </button>
                  <button
                    className="preset-chip"
                    onClick={() => handleApplyPreset('zerotrust')}
                  >
                    <Lock size={14} color="#34d399" /> <span>Zero-Trust CNSA 2.0 (2 Links)</span>
                  </button>
                  <button
                    className="preset-chip danger"
                    onClick={() => handleApplyPreset('legacy')}
                  >
                    <AlertTriangle size={14} color="#f87171" /> <span>Legacy Sweet32/Logjam (2 Links)</span>
                  </button>
                </div>

                <button
                  className="cockpit-run-btn"
                  onClick={() => handleRunSimulation(links, true)}
                  disabled={isSimulating}
                >
                  {isSimulating ? (
                    <RefreshCw size={15} className="spin" />
                  ) : (
                    <Play size={15} fill="currentColor" />
                  )}
                  <span>{isSimulating ? 'Simulating Stream...' : `Simulate ${links.length} Links & Live Audit`}</span>
                </button>
              </div>
            </GlassCard>

            {/* Split Grid: Left = Link Selector, Right = Active Link Configuration Form */}
            <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1rem' }}>
              {/* Left Column: Link List */}
              <GlassCard style={{ padding: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <div className="section-kicker">NETWORK LINKS ({links.length})</div>
                  <button
                    onClick={handleAddLink}
                    className="add-link-btn"
                    title="Add new IPsec tunnel link"
                  >
                    <Plus size={13} />
                    <span>Add Link</span>
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {links.map((lnk, idx) => {
                    const isSelected = idx === selectedLinkIndex
                    const trf = TRAFFIC_PROFILES.find(t => t.key === lnk.traffic) || TRAFFIC_PROFILES[0]
                    const enc = lnk.crypto.encryption

                    return (
                      <div
                        key={lnk.id || idx}
                        onClick={() => setSelectedLinkIndex(idx)}
                        className={`link-selector-card ${isSelected ? 'selected' : ''}`}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: isSelected ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                            {lnk.name}
                          </span>
                          {links.length > 1 && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                handleRemoveLink(idx)
                              }}
                              className="link-delete-btn"
                              title="Remove link"
                            >
                              <Trash2 size={12} />
                            </button>
                          )}
                        </div>

                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {lnk.source} ↔ {lnk.destination}
                        </div>

                        <div style={{ display: 'flex', gap: '0.35rem', marginTop: '6px', flexWrap: 'wrap' }}>
                          <span className={`mini-tag ${enc.includes('3DES') || enc.includes('DES') ? 'bad' : 'blue'}`}>
                            {enc}
                          </span>
                          <span className="mini-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                            {(() => {
                              const IconComp = TRAFFIC_ICONS[lnk.traffic] || Activity
                              return <IconComp size={11} color="currentColor" />
                            })()}
                            <span>{lnk.traffic.toUpperCase()}</span>
                          </span>
                          <span className="mini-tag">
                            IKEv{lnk.crypto.ike_version}
                          </span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </GlassCard>

              {/* Right Column: Detailed Configuration Editor */}
              {curLink && (
                <GlassCard style={{ padding: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
                    <div>
                      <div className="section-kicker">LINK CONFIGURATION EDITOR</div>
                      <h2 style={{ margin: '2px 0 0', fontSize: '1.1rem', fontWeight: 700 }}>
                        {curLink.name}
                      </h2>
                    </div>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      ID: {curLink.id}
                    </span>
                  </div>

                  {/* Section A: Endpoints & Mode */}
                  <div className="config-section">
                    <div className="config-section-title">1. ENDPOINT IDENTITIES &amp; TUNNEL MODE</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
                      <div>
                        <label className="config-label">SOURCE ENDPOINT:</label>
                        <input
                          type="text"
                          className="config-input"
                          value={curLink.source}
                          onChange={(e) => updateSelectedLink('source', e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="config-label">DESTINATION ENDPOINT:</label>
                        <input
                          type="text"
                          className="config-input"
                          value={curLink.destination}
                          onChange={(e) => updateSelectedLink('destination', e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="config-label">IPSEC OPERATING MODE:</label>
                        <select
                          className="config-select"
                          value={curLink.operating_mode}
                          onChange={(e) => updateSelectedLink('operating_mode', e.target.value)}
                        >
                          <option value="tunnel">Tunnel Mode</option>
                          <option value="transport">Transport Mode</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Section B: Cryptographic Suite */}
                  <div className="config-section">
                    <div className="config-section-title">2. CRYPTOGRAPHIC SUITE &amp; SA PROPOSALS</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.85rem' }}>
                      {/* Encryption Cipher */}
                      <div>
                        <label className="config-label">ENCRYPTION ALGORITHM:</label>
                        <select
                          className="config-select"
                          value={curLink.crypto.encryption}
                          onChange={(e) => {
                            const selected = CIPHER_OPTIONS.find(c => c.value === e.target.value)
                            updateSelectedLink('crypto.encryption', e.target.value)
                            if (selected) {
                              updateSelectedLink('crypto.key_length', selected.klen)
                              if (selected.isAead) {
                                updateSelectedLink('crypto.integrity', 'AEAD Combined (GCM Tag)')
                              }
                            }
                          }}
                        >
                          {CIPHER_OPTIONS.map(c => (
                            <option key={c.value} value={c.value}>{c.label}</option>
                          ))}
                        </select>
                      </div>

                      {/* Diffie-Hellman Group */}
                      <div>
                        <label className="config-label">DIFFIE-HELLMAN KEY EXCHANGE GROUP:</label>
                        <select
                          className="config-select"
                          value={curLink.crypto.dh_group_num}
                          onChange={(e) => {
                            const num = parseInt(e.target.value)
                            const selected = DH_OPTIONS.find(d => d.num === num)
                            updateSelectedLink('crypto.dh_group_num', num)
                            if (selected) {
                              updateSelectedLink('crypto.dh_group', selected.name)
                            }
                          }}
                        >
                          {DH_OPTIONS.map(d => (
                            <option key={d.num} value={d.num}>{d.label}</option>
                          ))}
                        </select>
                      </div>

                      {/* Integrity / MAC */}
                      <div>
                        <label className="config-label">INTEGRITY &amp; MAC TAG:</label>
                        <select
                          className="config-select"
                          value={curLink.crypto.integrity}
                          onChange={(e) => updateSelectedLink('crypto.integrity', e.target.value)}
                        >
                          {INTEGRITY_OPTIONS.map(i => (
                            <option key={i.value} value={i.value}>{i.label}</option>
                          ))}
                        </select>
                      </div>

                      {/* IKE Version & PFS */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                        <div>
                          <label className="config-label">IKE PROTOCOL:</label>
                          <select
                            className="config-select"
                            value={curLink.crypto.ike_version}
                            onChange={(e) => updateSelectedLink('crypto.ike_version', parseInt(e.target.value))}
                          >
                            <option value="2">IKEv2</option>
                            <option value="1">IKEv1</option>
                          </select>
                        </div>
                        <div>
                          <label className="config-label">FORWARD SECRECY (PFS):</label>
                          <select
                            className="config-select"
                            value={curLink.crypto.pfs_enabled ? 'true' : 'false'}
                            onChange={(e) => updateSelectedLink('crypto.pfs_enabled', e.target.value === 'true')}
                          >
                            <option value="true">Enabled</option>
                            <option value="false">Disabled</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Section C: Inner Application Traffic Profile */}
                  <div className="config-section">
                    <div className="config-section-title">3. TRANSFERRED INNER APPLICATION DATA</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.5rem' }}>
                      {TRAFFIC_PROFILES.map(tp => {
                        const IconComp = TRAFFIC_ICONS[tp.key] || Activity
                        const isSelected = curLink.traffic === tp.key
                        return (
                          <button
                            key={tp.key}
                            type="button"
                            className={`traffic-select-chip ${isSelected ? 'active' : ''}`}
                            onClick={() => updateSelectedLink('traffic', tp.key)}
                          >
                            <IconComp size={20} color={isSelected ? 'var(--accent-blue)' : '#94a3b8'} />
                            <div style={{ fontSize: '0.82rem', fontWeight: 700 }}>{tp.name}</div>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Section D: Real-World Channel Degradation (Netem) */}
                  <div className="config-section" style={{ borderBottom: 'none', marginBottom: 0 }}>
                    <div className="config-section-title">4. REAL-WORLD CHANNEL DEGRADATIONS (NETEM INJECTION)</div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <label className="config-label">GAUSSIAN JITTER:</label>
                          <span style={{ fontSize: '0.72rem', color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>
                            ±{curLink.degradation.jitter_ms} ms
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="50"
                          value={curLink.degradation.jitter_ms}
                          onChange={(e) => updateSelectedLink('degradation.jitter_ms', parseInt(e.target.value))}
                          style={{ width: '100%' }}
                        />
                      </div>

                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <label className="config-label">PACKET LOSS / DROPS:</label>
                          <span style={{ fontSize: '0.72rem', color: curLink.degradation.packet_loss_pct > 2 ? 'var(--accent-red)' : 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>
                            {curLink.degradation.packet_loss_pct}%
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="10"
                          step="0.5"
                          value={curLink.degradation.packet_loss_pct}
                          onChange={(e) => updateSelectedLink('degradation.packet_loss_pct', parseFloat(e.target.value))}
                          style={{ width: '100%' }}
                        />
                      </div>

                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <label className="config-label">PACKET REORDERING:</label>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                            {curLink.degradation.reorder_pct}%
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0"
                          max="5"
                          step="0.5"
                          value={curLink.degradation.reorder_pct}
                          onChange={(e) => updateSelectedLink('degradation.reorder_pct', parseFloat(e.target.value))}
                          style={{ width: '100%' }}
                        />
                      </div>
                    </div>
                  </div>
                </GlassCard>
              )}
            </div>
          </div>
        )}

        {/* VIEW 2: REAL-TIME SIMULATION RESULTS & MULTI-LINK AUDIT */}
        {activeTab === 'results' && (
          simulationResults ? (
          <div>
            {/* Live Streaming Operator Control Strip */}
            <GlassCard style={{ padding: '0.85rem 1.25rem', marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
                {isStreaming ? (
                  <div className="live-pulse-badge transmitting">
                    <span className="pulsing-beacon"></span>
                    <span>LIVE STREAM TRANSMITTING</span>
                  </div>
                ) : isAborted ? (
                  <div className="live-pulse-badge aborted">
                    <span className="stop-beacon"></span>
                    <span>STREAM ABORTED</span>
                  </div>
                ) : (
                  <div className="live-pulse-badge idle">
                    <span>STREAM READY</span>
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.45rem', fontFamily: 'monospace' }}>
                  <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-muted)' }}>ELAPSED:</span>
                  <span style={{ fontSize: '1.25rem', fontWeight: 900, color: isStreaming ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                    {formatElapsed(elapsedSeconds)}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '1.2rem', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  <span>Flow: <strong style={{ color: 'var(--text-primary)', fontWeight: 800 }}>{simulationResults.network_summary?.current_aggregate_pps || graphData.currentPps || 0} pkts/s</strong></span>
                  <span>Transferred: <strong style={{ color: 'var(--text-primary)', fontWeight: 800 }}>{(simulationResults.network_summary?.total_packets_streamed || 0).toLocaleString()} pkts</strong> <span style={{ color: 'var(--text-muted)' }}>({simulationResults.network_summary?.total_data_volume_mb || 0} MB)</span></span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                {isStreaming ? (
                  <button
                    className="cockpit-abort-btn"
                    onClick={handleAbortStream}
                  >
                    <Square size={13} fill="currentColor" />
                    <span>Abort Stream</span>
                  </button>
                ) : (
                  <button
                    className="cockpit-resume-btn"
                    onClick={handleResumeStream}
                  >
                    <Play size={13} fill="currentColor" />
                    <span>{isAborted ? 'Resume Stream' : 'Start Live Stream'}</span>
                  </button>
                )}

                <button
                  className="cockpit-reset-btn"
                  onClick={handleResetStream}
                >
                  <RotateCcw size={13} />
                  <span>Reset</span>
                </button>

                <button
                  type="button"
                  onClick={() => setIsReportModalOpen(true)}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '6px 14px',
                    borderRadius: '7px',
                    background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.2), rgba(37, 99, 235, 0.3))',
                    border: '1px solid rgba(56, 189, 248, 0.5)',
                    color: '#38bdf8',
                    fontSize: '0.78rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <FileText size={14} />
                  <span>Export Audit Report</span>
                </button>
              </div>
            </GlassCard>

            {/* Top Network Health Strip */}
            <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1rem', marginBottom: '1rem' }}>
              {/* Overall Network Scorecard */}
              <GlassCard style={{ padding: '1.25rem', display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                <div style={{
                  width: 104,
                  height: 104,
                  borderRadius: '50%',
                  border: `5px solid ${
                    simulationResults.network_summary.overall_compliance === 'PASS'
                      ? 'var(--accent-green)'
                      : simulationResults.network_summary.overall_compliance === 'FAIL'
                        ? 'var(--accent-red)'
                        : 'var(--accent-amber)'
                  }`,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  background: 'var(--glass-inner)',
                  boxShadow: `0 0 20px ${
                    simulationResults.network_summary.overall_compliance === 'PASS'
                      ? 'rgba(34, 197, 94, 0.2)'
                      : simulationResults.network_summary.overall_compliance === 'FAIL'
                        ? 'rgba(239, 68, 68, 0.2)'
                        : 'rgba(245, 158, 11, 0.2)'
                  }`
                }}>
                  <strong style={{ fontSize: '2.3rem', fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                    {simulationResults.network_summary.average_security_score}
                  </strong>
                  <span style={{ fontSize: '0.65rem', fontWeight: 700, color: 'var(--text-muted)', marginTop: '4px', letterSpacing: '0.04em' }}>
                    NETWORK AVG
                  </span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{
                    fontSize: '0.75rem',
                    fontWeight: 800,
                    padding: '3px 9px',
                    borderRadius: '4px',
                    alignSelf: 'flex-start',
                    background: simulationResults.network_summary.overall_compliance === 'PASS' ? 'var(--green-soft)' : simulationResults.network_summary.overall_compliance === 'FAIL' ? 'var(--red-soft)' : 'var(--amber-soft)',
                    color: simulationResults.network_summary.overall_compliance === 'PASS' ? 'var(--accent-green)' : simulationResults.network_summary.overall_compliance === 'FAIL' ? 'var(--accent-red)' : 'var(--accent-amber)',
                    letterSpacing: '0.04em'
                  }}>
                    {simulationResults.network_summary.overall_compliance} POSTURE
                  </div>
                  <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                    {simulationResults.network_summary.total_links} Concurrent Links
                  </h3>
                  <div style={{
                    fontSize: '0.78rem',
                    fontWeight: 700,
                    color: simulationResults.network_summary.total_active_threats > 0 ? 'var(--accent-red)' : 'var(--accent-green)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '5px'
                  }}>
                    {simulationResults.network_summary.total_active_threats > 0 ? (
                      <>
                        <AlertTriangle size={13} />
                        <span>{simulationResults.network_summary.total_active_threats} Vulnerabilities Detected</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck size={13} />
                        <span>All Links Compliant</span>
                      </>
                    )}
                  </div>
                </div>
              </GlassCard>

              {/* Real-time Oscilloscope Mini Card */}
              <GlassCard style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <div>
                    <div className="section-kicker">STREAM OSCILLOSCOPE</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                      Aggregate Throughput Telemetry
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '1.2rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    <span>Packets: <strong style={{ color: 'var(--text-primary)', fontWeight: 800 }}>{simulationResults.network_summary.total_packets_streamed.toLocaleString()}</strong></span>
                    <span>Volume: <strong style={{ color: 'var(--text-primary)', fontWeight: 800 }}>{simulationResults.network_summary.total_data_volume_mb} MB</strong></span>
                    <span>Window: <strong style={{ color: 'var(--accent-cyan)', fontWeight: 800 }}>15s</strong></span>
                  </div>
                </div>

                {/* Rolling 15-Second Oscilloscope SVG */}
                <div style={{ height: 65, width: '100%', position: 'relative' }}>
                  <svg width="100%" height="100%" preserveAspectRatio="none" viewBox="0 0 500 70">
                    <defs>
                      <linearGradient id="streamGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.45" />
                        <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>

                    {/* Guidelines */}
                    <line x1="0" y1="20" x2="500" y2="20" stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />
                    <line x1="0" y1="45" x2="500" y2="45" stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />

                    {/* Area */}
                    <path
                      d={graphData.areaPath}
                      fill="url(#streamGrad)"
                    />

                    {/* Waveform Line */}
                    <path
                      d={graphData.linePath}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />

                    {/* Leading Pointer */}
                    {isStreaming && (
                      <g>
                        <circle cx={graphData.leadX} cy={graphData.leadY} r="8" fill="#38bdf8" opacity="0.35">
                          <animate attributeName="r" values="5;10;5" dur="1.2s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.6;0.1;0.6" dur="1.2s" repeatCount="indefinite" />
                        </circle>
                        <circle cx={graphData.leadX} cy={graphData.leadY} r="4" fill="#38bdf8" />
                        <circle cx={graphData.leadX} cy={graphData.leadY} r="1.8" fill="#ffffff" />
                      </g>
                    )}
                  </svg>
                </div>

                {/* Dynamic Timeline Markers */}
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px', fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  <span>{elapsedSeconds <= 15 ? '0s (START)' : `-${15}s`}</span>
                  <span>{elapsedSeconds <= 15 ? '5s' : `-${10}s`}</span>
                  <span>{elapsedSeconds <= 15 ? '10s' : `-${5}s`}</span>
                  <span style={{ color: isStreaming ? 'var(--accent-cyan)' : 'var(--text-muted)', fontWeight: 700 }}>
                    {elapsedSeconds <= 15 ? '15s (END)' : `NOW (${elapsedSeconds}s)`}
                  </span>
                </div>
              </GlassCard>
            </div>

            {/* Multi-Link Cards Grid (Balanced 3 Columns) */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.25rem' }}>
              {simulationResults.links.map((lnk) => {
                const sec = lnk.security_assessment
                const ai = lnk.ai_traffic_intelligence
                const st = lnk.stream_telemetry
                const isSelected = inspectedLink?.id === lnk.id
                const isCapped = sec.veto_ceiling?.is_capped

                const statusColor = sec.compliance_status === 'PASS'
                  ? 'var(--accent-green)'
                  : sec.compliance_status === 'FAIL'
                    ? 'var(--accent-red)'
                    : 'var(--accent-amber)'

                return (
                  <GlassCard
                    key={lnk.id}
                    onClick={() => {
                      setInspectedLink(lnk)
                    }}
                    className={`sim-link-card ${isSelected ? 'selected' : ''}`}
                    style={{
                      padding: '1.15rem',
                      cursor: 'pointer',
                      border: isSelected ? '2px solid var(--accent-blue)' : '1px solid var(--glass-inner-border)',
                      background: isSelected ? 'rgba(56, 189, 248, 0.08)' : 'var(--glass-surface)',
                      boxShadow: isSelected ? '0 0 18px rgba(56, 189, 248, 0.22)' : 'none',
                      transition: 'all 0.2s ease',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.65rem' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <div style={{ fontSize: '0.92rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                              {lnk.name}
                            </div>
                            {isSelected && (
                              <span style={{
                                fontSize: '0.62rem',
                                fontWeight: 800,
                                padding: '2px 7px',
                                borderRadius: '3px',
                                background: 'rgba(56, 189, 248, 0.2)',
                                color: 'var(--accent-blue)',
                                border: '1px solid rgba(56, 189, 248, 0.4)',
                                letterSpacing: '0.04em'
                              }}>
                                INSPECTING
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                            {lnk.endpoints}
                          </div>
                        </div>

                        {/* Prominent Score Display */}
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
                          <div style={{
                            display: 'flex',
                            alignItems: 'baseline',
                            gap: '2px',
                            padding: '4px 10px',
                            borderRadius: '6px',
                            background: sec.compliance_status === 'PASS' ? 'var(--green-soft)' : sec.compliance_status === 'FAIL' ? 'var(--red-soft)' : 'var(--amber-soft)',
                            border: `1px solid ${sec.compliance_status === 'PASS' ? 'rgba(34,197,94,0.3)' : sec.compliance_status === 'FAIL' ? 'rgba(239,68,68,0.3)' : 'rgba(245,158,11,0.3)'}`
                          }}>
                            <span style={{ fontSize: '1.25rem', fontWeight: 900, color: statusColor, lineHeight: 1 }}>{sec.risk_score}</span>
                            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)' }}>/100</span>
                          </div>
                          {isCapped && (
                            <span style={{ fontSize: '0.62rem', fontWeight: 800, color: 'var(--accent-red)', marginTop: '2px' }}>
                              VETO CAPPED
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Suite & Telemetry Summary Facts */}
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.5rem', fontSize: '0.74rem', margin: '0.75rem 0' }}>
                        <div style={{ padding: '6px 8px', background: 'var(--glass-inner)', borderRadius: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Cipher: </span>
                          <strong>{sec.negotiated_suite.encryption || 'AES-GCM'}</strong>
                        </div>
                        <div style={{ padding: '6px 8px', background: 'var(--glass-inner)', borderRadius: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>DH Group: </span>
                          <strong>{sec.negotiated_suite.dh_group || 'Group 14'}</strong>
                        </div>
                        <div style={{ padding: '6px 8px', background: 'var(--glass-inner)', borderRadius: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>AI App: </span>
                          <strong style={{ color: 'var(--accent-blue)' }}>{ai.predicted_application}</strong>
                        </div>
                        <div style={{ padding: '6px 8px', background: 'var(--glass-inner)', borderRadius: '4px' }}>
                          <span style={{ color: 'var(--text-muted)' }}>Traffic: </span>
                          <strong>{st.total_packets.toLocaleString()} pkts</strong>
                          {st.dropped_packets > 0 && (
                            <span style={{ color: 'var(--accent-red)', marginLeft: '4px', fontWeight: 700 }}>
                              ({st.dropped_packets} drops)
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Clean Status Line */}
                    <div style={{ paddingTop: '0.45rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                      {sec.violations.length > 0 ? (
                        <div style={{ fontSize: '0.74rem', color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 700 }}>
                          <AlertTriangle size={13} />
                          <span>{sec.violations.length} Critical Security Flaws</span>
                        </div>
                      ) : (
                        <div style={{ fontSize: '0.74rem', color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 700 }}>
                          <ShieldCheck size={13} />
                          <span>NIST SP 800-77 Compliant</span>
                        </div>
                      )}
                    </div>
                  </GlassCard>
                )
              })}
            </div>

            {/* Detailed Link Inspector */}
            {inspectedLink && (
              <GlassCard style={{ padding: '1.5rem', marginTop: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.15rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.85rem' }}>
                  <div>
                    <div className="section-kicker">SELECTED LINK DEEP AUDIT</div>
                    <h2 style={{ margin: '3px 0 0', fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc' }}>
                      {inspectedLink.name} ({inspectedLink.endpoints})
                    </h2>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Mode: <strong style={{ color: 'var(--text-primary)' }}>{inspectedLink.configured_mode}</strong>
                    </span>
                    <div style={{
                      display: 'flex',
                      alignItems: 'baseline',
                      gap: '4px',
                      padding: '4px 12px',
                      borderRadius: '6px',
                      background: inspectedLink.security_assessment.compliance_status === 'PASS' ? 'var(--green-soft)' : inspectedLink.security_assessment.compliance_status === 'FAIL' ? 'var(--red-soft)' : 'var(--amber-soft)',
                      border: `1px solid ${inspectedLink.security_assessment.compliance_status === 'PASS' ? 'rgba(34,197,94,0.4)' : inspectedLink.security_assessment.compliance_status === 'FAIL' ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.4)'}`
                    }}>
                      <span style={{ fontSize: '1.25rem', fontWeight: 900, color: inspectedLink.security_assessment.compliance_status === 'PASS' ? 'var(--accent-green)' : inspectedLink.security_assessment.compliance_status === 'FAIL' ? 'var(--accent-red)' : 'var(--accent-amber)', lineHeight: 1 }}>
                        {inspectedLink.security_assessment.risk_score}
                      </span>
                      <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>/ 100</span>
                      <span style={{ fontSize: '0.75rem', fontWeight: 800, color: inspectedLink.security_assessment.compliance_status === 'PASS' ? 'var(--accent-green)' : inspectedLink.security_assessment.compliance_status === 'FAIL' ? 'var(--accent-red)' : 'var(--accent-amber)', marginLeft: '4px' }}>
                        [{inspectedLink.security_assessment.compliance_status}]
                      </span>
                    </div>
                  </div>
                </div>

                {/* 6-Pillar Rubric Cards Grid (Balanced 3x2 Grid) */}
                <div style={{ marginBottom: '1.25rem' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.65rem' }}>
                    6-PILLAR NIST SP 800-77 &amp; CNSA 2.0 AUDIT:
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.65rem' }}>
                    {Object.entries(inspectedLink?.security_assessment?.rubric_breakdown || {}).map(([key, pillar]) => {
                      const pct = Math.round((pillar.score / pillar.max_score) * 100)
                      const isGood = pillar.status === 'OPTIMAL' || pillar.status === 'COMPLIANT'
                      const isFail = pillar.status === 'CRITICAL_FAIL'
                      const pColor = isFail ? 'var(--accent-red)' : isGood ? 'var(--accent-green)' : 'var(--accent-amber)'

                      return (
                        <div
                          key={key}
                          style={{
                            padding: '0.8rem 0.95rem',
                            background: 'var(--glass-inner)',
                            border: `1px solid ${isFail ? 'rgba(248,113,113,0.3)' : 'var(--border-subtle)'}`,
                            borderRadius: 'var(--radius-sm)',
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'space-between'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                              {pillar.name}
                            </span>
                            <span style={{
                              fontSize: '0.92rem',
                              fontWeight: 900,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              background: isFail ? 'var(--red-soft)' : isGood ? 'var(--green-soft)' : 'var(--amber-soft)',
                              color: pColor,
                              display: 'flex',
                              alignItems: 'baseline',
                              gap: '2px'
                            }}>
                              <span>{pillar.score}</span>
                              <span style={{ fontSize: '0.68rem', fontWeight: 700, opacity: 0.8 }}>/{pillar.max_score}</span>
                            </span>
                          </div>

                          <div style={{ width: '100%', height: 5, borderRadius: 3, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
                            <div style={{
                              width: `${pct}%`,
                              height: '100%',
                              background: pColor,
                              borderRadius: 3
                            }} />
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Identified Threats & Vulnerabilities */}
                {inspectedLink.security_assessment.violations.length > 0 && (
                  <div style={{ marginTop: '1rem' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-red)', marginBottom: '0.5rem' }}>
                      IDENTIFIED VULNERABILITIES ({inspectedLink.security_assessment.violations.length}):
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                      {inspectedLink.security_assessment.violations.map((v, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '0.65rem 0.85rem',
                            borderRadius: 'var(--radius-sm)',
                            background: v.severity === 'CRITICAL' ? 'var(--red-soft)' : 'var(--amber-soft)',
                            border: `1px solid ${v.severity === 'CRITICAL' ? 'rgba(248,113,113,0.3)' : 'rgba(251,191,36,0.3)'}`
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: v.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                              [{v.severity}] {v.title}
                            </span>
                            <span style={{ fontSize: '0.68rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                              {v.cwe}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                            {v.description}
                          </div>
                          {v.remediation && (
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-primary)', marginTop: '3px' }}>
                              <strong>Remediation:</strong> {v.remediation}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </GlassCard>
            )}
          </div>
          ) : (
            <GlassCard style={{ padding: '3.5rem 2rem', textAlign: 'center', margin: '2rem 0' }}>
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 64,
                height: 64,
                borderRadius: '50%',
                background: 'rgba(56, 189, 248, 0.12)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                marginBottom: '1.25rem'
              }}>
                <RefreshCw size={28} color="#38bdf8" className="spin" />
              </div>
              <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: '#ffffff' }}>
                Initializing Live Multi-Link Wiretap Telemetry &amp; Sensor Mesh...
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', maxWidth: 520, margin: '0.65rem auto 1.5rem', lineHeight: 1.5 }}>
                Negotiating IKEv2 Phase 1/Phase 2 Security Associations, establishing virtual IPsec tunnels, and activating real-time packet stream telemetry.
              </p>
              <button
                className="cockpit-run-btn"
                onClick={() => handleRunSimulation(links, true)}
                style={{ margin: '0 auto' }}
              >
                <Play size={14} fill="currentColor" />
                <span>Launch Live Stream Now</span>
              </button>
            </GlassCard>
          )
        )}
      </main>
          {/* Intelligence Report Generator Modal */}
      <ReportExportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        mode="live"
        activeData={simulationResults}
        links={simulationResults?.links || links}
        elapsedSeconds={elapsedSeconds}
      />
    </div>
  )
}