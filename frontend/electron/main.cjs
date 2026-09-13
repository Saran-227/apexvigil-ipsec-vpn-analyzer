const { app, BrowserWindow, Menu } = require('electron')
const path = require('path')
const http = require('http')
const { spawn, exec } = require('child_process')

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

async function waitForService(host, port, endpoint = '', maxRetries = 30, interval = 500) {
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
    console.log('[Electron] Backend is already running on http://127.0.0.1:8000')
    return true
  }

  console.log('[Electron] Starting Python FastAPI Backend from:', REPO_ROOT)
  try {
    pythonProcess = spawn('python', ['run.py'], {
      cwd: REPO_ROOT,
      shell: true,
      stdio: 'pipe'
    })

    spawnedPython = true

    pythonProcess.stdout.on('data', (data) => {
      console.log(`[Python Backend] ${data.toString().trim()}`)
    })

    pythonProcess.stderr.on('data', (data) => {
      console.error(`[Python Backend Err] ${data.toString().trim()}`)
    })

    pythonProcess.on('close', (code) => {
      console.log(`[Python Backend] Exited with code ${code}`)
    })

    const ready = await waitForService('127.0.0.1', 8000, '/api/health', 25, 600)
    if (ready) {
      console.log('[Electron] Backend successfully initialized on port 8000.')
      return true
    } else {
      console.warn('[Electron] Backend initialization timed out, continuing anyway...')
      return false
    }
  } catch (err) {
    console.error('[Electron] Failed to spawn Python backend:', err)
    return false
  }
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1460,
    height: 940,
    minWidth: 1100,
    minHeight: 720,
    title: 'NTRO IPsec Intelligence Platform (SIH26160)',
    backgroundColor: '#090d16',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true
    }
  })

  // Set dark cyber-defense menu
  const menuTemplate = [
    {
      label: 'Platform',
      submenu: [
        { label: 'Reload Workspace', accelerator: 'CmdOrCtrl+R', click: () => mainWindow.reload() },
        { label: 'Force Reload', accelerator: 'CmdOrCtrl+Shift+R', click: () => mainWindow.webContents.reloadIgnoringCache() },
        { type: 'separator' },
        { label: 'Quit NTRO Platform', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() }
      ]
    },
    {
      label: 'View',
      submenu: [
        { label: 'Toggle Full Screen', accelerator: 'F11', click: () => mainWindow.setFullScreen(!mainWindow.isFullScreen()) },
        { label: 'Actual Size', accelerator: 'CmdOrCtrl+0', click: () => mainWindow.webContents.setZoomLevel(0) },
        { label: 'Zoom In', accelerator: 'CmdOrCtrl+=', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() + 0.5) },
        { label: 'Zoom Out', accelerator: 'CmdOrCtrl+-', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() - 0.5) },
        { type: 'separator' },
        { label: 'Developer Tools', accelerator: 'CmdOrCtrl+Shift+I', click: () => mainWindow.webContents.toggleDevTools() }
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
  await ensureBackend()

  const win = createMainWindow()

  // Check if Vite Dev Server is running on port 5173
  const isViteUp = await isPortOpen('127.0.0.1', 5173)
  if (isViteUp) {
    console.log('[Electron] Loading frontend from Vite dev server: http://127.0.0.1:5173')
    win.loadURL('http://127.0.0.1:5173')
  } else {
    // If Vite dev server is not running, check for built dist/index.html
    const distIndex = path.join(FRONTEND_DIR, 'dist', 'index.html')
    const fs = require('fs')
    if (fs.existsSync(distIndex)) {
      console.log('[Electron] Loading production bundle:', distIndex)
      win.loadFile(distIndex)
    } else {
      console.log('[Electron] Loading via backend on http://127.0.0.1:8000')
      win.loadURL('http://127.0.0.1:8000')
    }
  }
}

function cleanupProcesses() {
  if (spawnedPython && pythonProcess) {
    console.log('[Electron] Terminating Python backend...')
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
