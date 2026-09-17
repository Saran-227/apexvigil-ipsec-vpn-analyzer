import React from 'react'
import { Routes, Route } from 'react-router-dom'
import WorkspaceHub from './pages/WorkspaceHub'
import Dashboard from './pages/Dashboard'
import RealtimeCockpit from './pages/RealtimeCockpit'
import { useDashboardData } from './hooks/useDashboardData'

export default function App() {
  const data = useDashboardData()

  return (
    <Routes>
      {/* 1. Workstation Hub (Mode Selection Screen) */}
      <Route
        path="/"
        element={
          <WorkspaceHub
            connection={data.connection}
            samples={data.samples}
            onSelectSample={data.onSelectSample}
            tournamentData={data.tournamentData}
          />
        }
      />

      {/* 2. Forensic PCAP Analysis Dashboard */}
      <Route
        path="/pcap"
        element={
          <Dashboard
            {...data}
            theme="dark"
            toggleTheme={() => {}}
          />
        }
      />

      {/* 3. Real-Time Live Stream Analysis Cockpit */}
      <Route
        path="/realtime"
        element={
          <RealtimeCockpit
            connection={data.connection}
          />
        }
      />
    </Routes>
  )
}
