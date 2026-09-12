import { useState, useEffect } from 'react'
import { fetchHealth, fetchSamples, analyzeSample, analyzeUpload, fetchTournament } from '../services/api'
import { mapBackendReport } from '../adapters/backendAdapter'

const DEFAULT_SAMPLES = [
  {
    id: "golden_audit",
    title: "Golden IKEv2 VoIP (NIST Full Audit)",
    description: "AES-256-GCM, PRF_SHA256, DH Group 19, 557 packets.",
    tag: "GOLDEN",
    pcap: "sih26_asim_golden.pcap"
  },
  {
    id: "secure_voip",
    title: "Secure IKEv2 VoIP (Transport Mode)",
    description: "AES-CBC-128, HMAC-SHA256, DH Group 14. NIST compliant.",
    tag: "SECURE",
    pcap: "exp_002_voip_transport_aes_gcm_16_128_1789042405.pcapng"
  },
  {
    id: "nist_weak_ikev1",
    title: "NIST Non-Compliant (IKEv1 / 3DES / MD5)",
    description: "Legacy 3DES-CBC, MD5, DH Group 2. Critical CVE warnings.",
    tag: "CRITICAL_FAIL",
    pcap: "exp_003_ikev1_legacy_3des_md5.pcapng"
  },
  {
    id: "high_jitter_voip",
    title: "High-Jitter Voice VoIP Flow",
    description: "G.711 / Opus payload dynamics, small frame distribution.",
    tag: "WIRETAP",
    pcap: "exp_001_voip_tunnel_aes_cbc_12_128_1789042405.pcapng"
  },
  {
    id: "encrypted_video",
    title: "Encrypted Video Stream (1080p)",
    description: "High bitrate, variable packet size, bursty inter-arrival.",
    tag: "WIRETAP",
    pcap: "exp_005_video_tunnel_aes_gcm_16_256_1789042405.pcapng"
  },
  {
    id: "bulk_transfer",
    title: "Bulk Data / Backup Transfer",
    description: "Full MTU frame saturation (1420-1500B), sustained throughput.",
    tag: "WIRETAP",
    pcap: "exp_007_bulk_tunnel_aes_cbc_12_128_1789042405.pcapng"
  }
]

const DEFAULT_EXEC_SUMMARY = {
  target_pcap: 'sih26_asim_golden.pcap',
  total_packets: 557,
  esp_packets: 553,
  ike_packets: 4,
  session_duration_sec: 142.1,
  active_payload_duration_sec: 20.6,
  spi_pair: '0xc56d1914 <-> 0xcd0440ee',
  compliance_status: 'PASS',
  risk_level: 'LOW',
  risk_score: 100,
  nist_sp800_77_posture: 'COMPLIANT DEFENSE POSTURE'
}

const DEFAULT_AI_DATA = {
  traffic_classification: {
    predicted_primary_profile: 'voip',
    display_profile: 'VOIP + BULK / DATA (Concurrent Bimodal Flow)',
    confidence_score: 0.613,
    is_concurrent_traffic: true,
    active_applications: ['voip', 'bulk'],
    ranked_classes: [
      { class_name: 'bulk', probability: 0.613 },
      { class_name: 'voip', probability: 0.383 },
      { class_name: 'mixed', probability: 0.004 },
      { class_name: 'chat', probability: 0.000 }
    ]
  },
  operational_mode: {
    predicted_mode: 'TUNNEL',
    confidence_score: 1.0
  },
  key_flow_metrics: {
    mean_packet_length: 832.8,
    std_packet_length: 563.3,
    mean_iat_ms: 37.1,
    burstiness_index: 0.68,
    small_packet_ratio: 0.383,
    large_packet_ratio: 0.613
  },
  average_bytes_sec: 15800,
  temporal_window_breakdown: [
    { time_offset_sec: 0.0, duration_sec: 1.5, packet_count: 4, predicted_class: 'ike_signaling', confidence: 1.0, is_control_plane: true },
    { time_offset_sec: 1.5, duration_sec: 1.5, packet_count: 38, predicted_class: 'voip+bulk', confidence: 0.95, is_control_plane: false },
    { time_offset_sec: 3.0, duration_sec: 1.5, packet_count: 42, predicted_class: 'voip+bulk', confidence: 0.95, is_control_plane: false },
    { time_offset_sec: 4.5, duration_sec: 1.5, packet_count: 35, predicted_class: 'voip+bulk', confidence: 0.95, is_control_plane: false },
    { time_offset_sec: 6.0, duration_sec: 1.5, packet_count: 40, predicted_class: 'voip+bulk', confidence: 0.95, is_control_plane: false }
  ],
  flow_dynamics_reconciliation: {
    status: "BIMODAL_CONCURRENCY_IDENTIFIED",
    mean_length: 832.8,
    std_length: 563.3,
    small_ratio: 0.383,
    large_ratio: 0.613,
    resolution_advisory: "Decomposed bimodal flow into concurrent multi-application streams: Active Voice RTP Sub-stream (38.3%) concurrent with High-MTU Bulk/Data Stream or Tunnel Padding (61.3%). Marked as CONCURRENT (VoIP + Bulk/Data)."
  }
}

const DEFAULT_AUDIT_DATA = {
  compliance_status: 'PASS',
  risk_score: 100,
  negotiated_suite: {
    encryption: 'AES-256-GCM',
    auth_method: 'Pre-Shared Key (PSK)',
    spi_pair: '0xc56d1914 <-> 0xcd0440ee',
    key_length: 256,
    integrity: 'None (AEAD Integrated in GCM)',
    prf: 'PRF_HMAC_SHA2_256',
    dh_group: 'Group 19 (ECP-256)',
    pfs_status: 'ENABLED',
    replay_protection: 'RFC 4303 Active (0 Duplicates)',
    replay_window_width: 'Undeterminable via Passive Wiretap (Gateway Local)',
    key_lifetime: 'Autonomous Gateway Policy (RFC 7296)'
  },
  violations: []
}

const INITIAL_STATE = {
  security: {
    riskScore: 100,
    riskLevel: 'LOW',
    complianceStatus: 'PASS',
    postureLabel: 'COMPLIANT DEFENSE POSTURE',
    anomalyDetected: false,
    findings: []
  },
  endpoints: {
    peerIp: '172.28.0.2 ↔ 172.28.0.3',
    protocol: 'IKEv2 / ESP',
    encryption: 'AES-256-GCM',
    authMethod: 'Pre-Shared Key (PSK)',
    uptimeLabel: '557 Packets (553 ESP)'
  },
  auditData: DEFAULT_AUDIT_DATA,
  ikeDetails: { ike_version: 2, nat_traversal: false },
  aiData: DEFAULT_AI_DATA,
  execSummary: DEFAULT_EXEC_SUMMARY
}

export function useDashboardData() {
  const [connection, setConnection] = useState('ONLINE')
  const [samples, setSamples] = useState(DEFAULT_SAMPLES)
  const [selectedSample, setSelectedSample] = useState(DEFAULT_SAMPLES[0])
  const [activeFilename, setActiveFilename] = useState(DEFAULT_SAMPLES[0].pcap)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  const [tournamentData, setTournamentData] = useState(null)

  // Telemetry state
  const [dashboardData, setDashboardData] = useState(INITIAL_STATE)

  // Initialize live connection and fetch initial data
  useEffect(() => {
    let mounted = true

    async function init() {
      try {
        const [health, sampleList, tournament] = await Promise.all([
          fetchHealth().catch(() => null),
          fetchSamples().catch(() => []),
          fetchTournament().catch(() => null)
        ])

        if (!mounted) return

        if (health && health.status === 'ONLINE') {
          setConnection('LIVE')
          if (sampleList && sampleList.length > 0) {
            setSamples(sampleList)
            const defaultSample = sampleList.find(s => s.id === 'golden_audit') || sampleList[0]
            if (defaultSample) {
              setSelectedSample(defaultSample)
              setActiveFilename(defaultSample.pcap)
              loadSampleAnalysis(defaultSample.pcap)
            }
          }
          setTournamentData(tournament)
        }
      } catch (err) {
        console.warn('Live API connection initializing:', err)
      }
    }

    init()
    return () => { mounted = false }
  }, [])

  async function loadSampleAnalysis(pcapFilename) {
    setIsAnalyzing(true)
    setError(null)
    try {
      const report = await analyzeSample(pcapFilename)
      const mapped = mapBackendReport(report)
      if (mapped) {
        setDashboardData(mapped)
      }
    } catch (err) {
      console.warn('Backend query notice:', err)
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleSelectSample(sample) {
    setSelectedSample(sample)
    setActiveFilename(sample.pcap)
    await loadSampleAnalysis(sample.pcap)
  }

  async function handleUploadFile(file) {
    setIsAnalyzing(true)
    setSelectedSample(null)
    setActiveFilename(file.name)
    setError(null)
    try {
      const report = await analyzeUpload(file)
      const mapped = mapBackendReport(report)
      if (mapped) {
        setDashboardData(mapped)
      }
    } catch (err) {
      console.error('Failed to analyze uploaded file:', err)
      setError(err.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  return {
    ...dashboardData,
    connection,
    samples,
    selectedSample,
    activeFilename,
    isAnalyzing,
    error,
    tournamentData,
    onSelectSample: handleSelectSample,
    onUploadFile: handleUploadFile
  }
}
