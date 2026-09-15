const { app, BrowserWindow, Menu, ipcMain, dialog } = require('electron')
const path = require('path')
const http = require('http')
const { spawn, exec } = require('child_process')
const fs = require('fs')

let mainWindow = null
let pythonProcess = null
let spawnedPython = false

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const FRONTEND_DIR = path.resolve(__dirname, '..')

function isPortOpen(host, port, endpoint = '') {
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: endpoint, timeout: 1000 }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 500)
    })
    req.on('error', () => resolve(false))
    req.on('timeout', () => {
      req.destroy()
      resolve(false)
    })
  })
}

async function waitForService(host, port, endpoint = '', maxRetries = 35, interval = 500) {
  for (let i = 0; i < maxRetries; i++) {
    const ok = await isPortOpen(host, port, endpoint)
    if (ok) return true
    await new Promise((r) => setTimeout(r, interval))
  }
  return false
}

async function ensureBackend() {
  const isBackendUp = await isPortOpen('127.0.0.1', 8000, '/api/health')
  if (isBackendUp) {
    console.log('[Electron] Python FastAPI backend is active on http://127.0.0.1:8000')
    return true
  }

  console.log('[Electron] Spawning Python FastAPI backend daemon from:', REPO_ROOT)
  try {
    pythonProcess = spawn('python', ['run.py'], {
      cwd: REPO_ROOT,
      shell: true,
      stdio: 'pipe'
    })

    spawnedPython = true

    pythonProcess.stdout.on('data', (data) => {
      const msg = data.toString().trim()
      if (msg) console.log(`[Python API] ${msg}`)
    })

    pythonProcess.stderr.on('data', (data) => {
      const msg = data.toString().trim()
      if (msg) console.error(`[Python API Err] ${msg}`)
    })

    pythonProcess.on('close', (code) => {
      console.log(`[Python API] Process exited with code ${code}`)
    })

    const ready = await waitForService('127.0.0.1', 8000, '/api/health', 35, 600)
    if (ready) {
      console.log('[Electron] Backend successfully initialized on port 8000.')
      return true
    } else {
      console.warn('[Electron] Backend health-check timed out. Continuing...')
      return false
    }
  } catch (err) {
    console.error('[Electron] Failed to spawn Python backend:', err)
    return false
  }
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1480,
    height: 940,
    minWidth: 1140,
    minHeight: 740,
    title: 'NTRO IPsec Intelligence Platform (SIH26160) - Desktop Edition',
    backgroundColor: '#090d16',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true
    }
  })

  const menuTemplate = [
    {
      label: 'Platform',
      submenu: [
        {
          label: 'Open PCAP File...',
          accelerator: 'CmdOrCtrl+O',
          click: async () => {
            const res = await dialog.showOpenDialog(mainWindow, {
              title: 'Select IPsec PCAP Capture',
              properties: ['openFile'],
              filters: [{ name: 'PCAP Files', extensions: ['pcap', 'pcapng'] }]
            })
            if (!res.canceled && res.filePaths.length > 0) {
              mainWindow.webContents.send('pcap:selected', res.filePaths[0])
            }
          }
        },
        { type: 'separator' },
        { label: 'Reload View', accelerator: 'CmdOrCtrl+R', click: () => mainWindow.reload() },
        { label: 'Force Reload', accelerator: 'CmdOrCtrl+Shift+R', click: () => mainWindow.webContents.reloadIgnoringCache() },
        { type: 'separator' },
        { label: 'Quit NTRO Platform', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() }
      ]
    },
    {
      label: 'View',
      submenu: [
        { label: 'Toggle Full Screen', accelerator: 'F11', click: () => mainWindow.setFullScreen(!mainWindow.isFullScreen()) },
        { label: 'Reset Zoom', accelerator: 'CmdOrCtrl+0', click: () => mainWindow.webContents.setZoomLevel(0) },
        { label: 'Zoom In', accelerator: 'CmdOrCtrl+=', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() + 0.5) },
        { label: 'Zoom Out', accelerator: 'CmdOrCtrl+-', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() - 0.5) },
        { type: 'separator' },
        { label: 'Toggle Developer Tools', accelerator: 'CmdOrCtrl+Shift+I', click: () => mainWindow.webContents.toggleDevTools() }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'NIST SP 800-77 Audit Specs',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'NTRO Security Framework (SIH26160)',
              message: 'NIST SP 800-77 Rev. 1 & NSA CNSA 2.0 Compliant Cryptographic Audit Engine with AI-Driven Encrypted Traffic Profiling.'
            })
          }
        }
      ]
    }
  ]

  const menu = Menu.buildFromTemplate(menuTemplate)
  Menu.setApplicationMenu(menu)

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })

  return mainWindow
}

async function startApplication() {
  ipcMain.handle('dialog:openPcap', async () => {
    const res = await dialog.showOpenDialog(mainWindow, {
      title: 'Select IPsec PCAP Capture',
      properties: ['openFile'],
      filters: [{ name: 'PCAP Files', extensions: ['pcap', 'pcapng'] }]
    })
    return res.canceled ? null : res.filePaths[0]
  })

  ipcMain.handle('app:version', () => '2.0.0-desktop')

  await ensureBackend()

  const win = createMainWindow()

  const isViteUp = await isPortOpen('127.0.0.1', 5173)
  if (isViteUp) {
    console.log('[Electron] Connected to active Vite Dev Server on http://127.0.0.1:5173')
    win.loadURL('http://127.0.0.1:5173')
  } else {
    const distIndex = path.join(FRONTEND_DIR, 'dist', 'index.html')
    if (fs.existsSync(distIndex)) {
      console.log('[Electron] Loading bundled standalone frontend from:', distIndex)
      win.loadFile(distIndex)
    } else {
      console.log('[Electron] Vite server not running. Starting Vite dev server...')
      const viteProc = spawn('npx', ['vite', '--port', '5173'], {
        cwd: FRONTEND_DIR,
        shell: true,
        stdio: 'pipe'
      })
      await waitForService('127.0.0.1', 5173, '', 30, 400)
      win.loadURL('http://127.0.0.1:5173')
    }
  }
}

function cleanupProcesses() {
  if (spawnedPython && pythonProcess) {
    console.log('[Electron] Terminating spawned Python backend...')
    if (process.platform === 'win32') {
      exec(`taskkill /pid ${pythonProcess.pid} /T /F`, (err) => {
        if (err) console.error('[Electron] Error killing Python process:', err.message)
      })
    } else {
      pythonProcess.kill('SIGTERM')
    }
    pythonProcess = null
  }
}

app.whenReady().then(startApplication)

app.on('window-all-closed', () => {
  cleanupProcesses()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

app.on('before-quit', () => {
  cleanupProcesses()
})
