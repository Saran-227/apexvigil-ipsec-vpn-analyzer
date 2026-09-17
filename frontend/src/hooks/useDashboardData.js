import { useState, useEffect } from 'react'
import { fetchHealth, analyzeUpload } from '../services/api'
import { mapBackendReport } from '../adapters/backendAdapter'

export function useDashboardData() {
  const [connection, setConnection] = useState('ONLINE')
  const [activeFilename, setActiveFilename] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState(null)

  // Unanalyzed initial state: no presets, no default analysis
  const [dashboardData, setDashboardData] = useState({
    auditData: null,
    security: null,
    endpoints: null,
    execSummary: null,
    aiData: null,
    ikeDetails: null,
    events: [],
    chartData: []
  })

  useEffect(() => {
    let mounted = true
    async function init() {
      try {
        const health = await fetchHealth().catch(() => null)
        if (!mounted) return
        if (health && health.status === 'ONLINE') {
          setConnection('LIVE')
        }
      } catch (err) {
        console.warn('Backend connection notice:', err)
      }
    }
    init()
    return () => { mounted = false }
  }, [])

  async function handleUploadFile(file) {
    setIsAnalyzing(true)
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
      setError(err.message || 'File analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  return {
    ...dashboardData,
    hasAnalysis: Boolean(dashboardData?.auditData),
    connection,
    activeFilename,
    isAnalyzing,
    error,
    onUploadFile: handleUploadFile
  }
}
