const { spawn, exec } = require('child_process')
const http = require('http')
const path = require('path')

const FRONTEND_DIR = path.resolve(__dirname, '..')

function isPortOpen(host, port) {
  return new Promise((resolve) => {
    const req = http.get({ host, port, timeout: 800 }, (res) => {
      resolve(res.statusCode >= 200 && res.statusCode < 500)
    })
    req.on('error', () => resolve(false))
    req.on('timeout', () => {
      req.destroy()
      resolve(false)
    })
  })
}

async function waitForVite(maxRetries = 40, interval = 400) {
  for (let i = 0; i < maxRetries; i++) {
    const ok = await isPortOpen('127.0.0.1', 5173)
    if (ok) return true
    await new Promise((r) => setTimeout(r, interval))
  }
  return false
}

async function run() {
  console.log('[DevRunner] Checking if Vite dev server is already active on :5173...')
  let viteProcess = null
  const alreadyUp = await isPortOpen('127.0.0.1', 5173)

  if (!alreadyUp) {
    console.log('[DevRunner] Starting Vite Dev Server...')
    viteProcess = spawn('npx', ['vite'], {
      cwd: FRONTEND_DIR,
      shell: true,
      stdio: 'inherit'
    })

    console.log('[DevRunner] Waiting for Vite on http://127.0.0.1:5173...')
    const ready = await waitForVite()
    if (!ready) {
      console.error('[DevRunner] Vite did not start in time. Exiting.')
      process.exit(1)
    }
  } else {
    console.log('[DevRunner] Vite is already running on :5173.')
  }

  console.log('[DevRunner] Launching Electron native window...')
  const electronProcess = spawn('npx', ['electron', 'electron/main.cjs'], {
    cwd: FRONTEND_DIR,
    shell: true,
    stdio: 'inherit'
  })

  electronProcess.on('close', (code) => {
    console.log(`[DevRunner] Electron closed with code ${code}. Cleaning up...`)
    if (viteProcess) {
      if (process.platform === 'win32') {
        exec(`taskkill /pid ${viteProcess.pid} /T /F`, () => process.exit(code || 0))
      } else {
        viteProcess.kill('SIGTERM')
        process.exit(code || 0)
      }
    } else {
      process.exit(code || 0)
    }
  })
}

run().catch((err) => {
  console.error('[DevRunner] Fatal error:', err)
  process.exit(1)
})
