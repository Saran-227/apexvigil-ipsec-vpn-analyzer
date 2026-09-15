import React, { useState, useRef } from 'react'
import GlassCard from './GlassCard'
import { Upload, FileCode, Loader2, AlertCircle } from 'lucide-react'

export default function PcapIngestion({
  onUploadFile,
  isAnalyzing = false,
  activeFilename = ''
}) {
  const [dragActive, setDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [fileError, setFileError] = useState(null)
  const fileInputRef = useRef(null)

  const processFile = (file) => {
    setFileError(null)
    const ext = file.name.toLowerCase()
    if (!ext.endsWith('.pcap') && !ext.endsWith('.pcapng')) {
      setFileError('Invalid file format. Only .pcap and .pcapng files are permitted.')
      return
    }
    setSelectedFile(file)
    if (onUploadFile) {
      onUploadFile(file)
    }
  }

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0])
    }
  }

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0])
    }
  }

  return (
    <GlassCard className="pcap-ingestion-card" style={{ padding: '1.75rem' }}>
      <div className="card-title-row" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div className="icon-wrapper" style={{ width: 34, height: 34, borderRadius: 8 }}>
            <Upload size={18} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1.02rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              Capture Ingestion
            </h3>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Upload an IPsec packet capture (.pcap / .pcapng) to perform audit
            </span>
          </div>
        </div>

        {activeFilename && (
          <div style={{
            fontSize: '0.78rem',
            fontFamily: 'monospace',
            padding: '4px 12px',
            background: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: '6px',
            color: 'var(--accent-blue)',
            fontWeight: 700
          }}>
            Active: {activeFilename}
          </div>
        )}
      </div>

      {/* Clean Drag & Drop Upload Zone */}
      <div
        className={`drop-zone ${dragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        style={{
          border: `2px dashed ${dragActive ? 'var(--accent-blue)' : 'rgba(255, 255, 255, 0.15)'}`,
          borderRadius: '12px',
          padding: '2.5rem 1.5rem',
          textAlign: 'center',
          cursor: isAnalyzing ? 'wait' : 'pointer',
          background: dragActive ? 'rgba(56, 189, 248, 0.08)' : 'rgba(255, 255, 255, 0.02)',
          transition: 'all 0.2s ease',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '0.75rem'
        }}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: 'none' }}
          onChange={handleFileChange}
          disabled={isAnalyzing}
        />

        <div style={{
          width: 52,
          height: 52,
          borderRadius: '50%',
          background: isAnalyzing ? 'rgba(56, 189, 248, 0.12)' : 'rgba(255, 255, 255, 0.05)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          {isAnalyzing ? (
            <Loader2 size={26} className="spin" color="var(--accent-blue)" />
          ) : (
            <FileCode size={26} color="var(--accent-blue)" />
          )}
        </div>

        <div>
          <div style={{ fontWeight: 700, fontSize: '1rem', color: '#ffffff' }}>
            {isAnalyzing
              ? 'Analyzing Capture File...'
              : selectedFile
                ? selectedFile.name
                : 'Drop .pcap or .pcapng capture file here'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {isAnalyzing
              ? 'Executing cryptographic audit & flow inference'
              : selectedFile
                ? `${(selectedFile.size / 1024).toFixed(1)} KB • Click to change file`
                : 'or click to browse local files (strictly .pcap / .pcapng)'}
          </div>
        </div>
      </div>

      {fileError && (
        <div style={{
          marginTop: '1rem',
          padding: '0.65rem 1rem',
          borderRadius: '8px',
          background: 'var(--red-soft)',
          border: '1px solid var(--accent-red)',
          color: 'var(--accent-red)',
          fontSize: '0.82rem',
          fontWeight: 600,
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <AlertCircle size={16} />
          <span>{fileError}</span>
        </div>
      )}
    </GlassCard>
  )
}
