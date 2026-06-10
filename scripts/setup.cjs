const { execSync } = require('child_process')
const fs = require('fs')
const path = require('path')
const os = require('os')
const readline = require('readline')

const CFG = path.join(os.homedir(), '.sentinel-oracle')

function ts(cmd, opts = {}) {
  const bin = process.platform === 'win32'
    ? '"C:\\Program Files\\Tailscale\\tailscale.exe"'
    : 'tailscale'
  try {
    return execSync(`${bin} ${cmd}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, ...opts }).trim()
  } catch {
    return ''
  }
}

function sh(cmd, opts = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000, ...opts }).trim()
  } catch {
    return ''
  }
}

function ask(query) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise(resolve => rl.question(query, a => { rl.close(); resolve(a.trim().toLowerCase()) }))
}

function readJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch { return {} }
}

async function main() {
  console.log()
  console.log('  Sentinel Oracle — Setup')
  console.log('  ' + '─'.repeat(40))
  console.log()

  // ── Node.js ──
  const nodeVer = process.version
  const match = nodeVer.match(/^v(\d+)/)
  if (!match || parseInt(match[1]) < 20) {
    console.error('  ✖ Node.js >= 20 required (got ' + nodeVer + ')')
    process.exit(1)
  }
  console.log('  ✓ Node.js ' + nodeVer)

  // ── TLS certs ──
  const keyPath = path.join(CFG, 'server.key')
  const certPath = path.join(CFG, 'server.cert')
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    console.log('  ✓ TLS certificates found')
  } else {
    console.log('  … TLS certificates not found')
    const ans = await ask('    Generate self-signed certs? (Y/n) ')
    if (ans !== 'n') {
      fs.mkdirSync(CFG, { recursive: true })
      sh(`openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=sentinel-oracle"`)
      console.log('  ✓ TLS certificates created')
    } else {
      console.log('  ✖ TLS certs required — generate with openssl or use Tailscale Funnel')
      console.log()
    }
  }

  // ── Tailscale ──
  const tsInstalled = fs.existsSync('C:\\Program Files\\Tailscale\\tailscale.exe')

  if (tsInstalled) {
    console.log('  ✓ Tailscale installed')

    const statusJson = ts('status --json')
    const status = (() => { try { return JSON.parse(statusJson) } catch { return {} } })()
    const isAuthed = status.BackendState === 'Running' || status.BackendState === 'Starting'

    if (!isAuthed) {
      console.log('  … Tailscale not authenticated')
      const ans = await ask('    Run tailscale up? (Y/n) ')
      if (ans !== 'n') {
        console.log('    (a browser window will open for authentication)')
        ts('up', { stdio: 'inherit', timeout: 120000 })
        console.log('  ✓ Tailscale authenticated')
      }
    } else {
      console.log('  ✓ Tailscale authenticated')
    }

    // Check if funnel is already active for our port
    const funnelJson = ts('funnel status --json')
    let funnelActive = false
    try {
      const f = JSON.parse(funnelJson)
      const tcp = f.TCP || {}
      for (const [port, cfg] of Object.entries(tcp)) {
        const handlers = cfg.Handlers || {}
        for (const h of Object.values(handlers)) {
          if (h.Proxy && h.Proxy.includes(':3443')) funnelActive = true
        }
      }
    } catch {}

    if (funnelActive) {
      console.log('  ✓ Tailscale Funnel active on port 3443')
    } else {
      // Try serve (non-funnel)
      const serveJson = ts('serve status --json')
      let serveActive = false
      try {
        const s = JSON.parse(serveJson)
        const tcp = s.TCP || {}
        for (const [port, cfg] of Object.entries(tcp)) {
          const handlers = cfg.Handlers || {}
          for (const h of Object.values(handlers)) {
            if (h.Proxy && h.Proxy.includes(':3443')) serveActive = true
          }
        }
      } catch {}

      if (serveActive) {
        console.log('  ✓ Tailscale serve active for port 3443')
        console.log('  … Funnel not enabled — phone cannot reach server without Tailscale installed')
        const ans = await ask('    Enable Funnel on your tailnet and upgrade serve to funnel? (Y/n) ')
        if (ans !== 'n') {
          // Get the enable URL from the error message
          const funnelErr = ts('funnel --bg 3443', { stdio: ['pipe', 'pipe', 'pipe'] })
          const match = funnelErr.match(/https:\/\/[^\s]+/)
          if (match) {
            console.log('    Open this URL in your browser to enable Funnel:')
            console.log('    ' + match[0])
            console.log('    After enabling, press Enter to continue.')
            await ask('    Press Enter when Funnel is enabled… ')
          }
          console.log('    Running tailscale funnel --bg 3443…')
          ts('funnel --bg 3443', { stdio: 'inherit', timeout: 30000 })
          console.log('  ✓ Tailscale Funnel active — public HTTPS URL available')
        }
      } else {
        console.log('  … Tailscale not configured to proxy Oracle')
        const ans = await ask('    Activate Tailscale Funnel for zero-config HTTPS? (Y/n) ')
        if (ans !== 'n') {
          // First try — may fail if Funnel not enabled on tailnet
          const out = ts('funnel --bg 3443', { stdio: ['pipe', 'pipe', 'pipe'] })
          if (out.includes('not enabled')) {
            const match = out.match(/https:\/\/[^\s]+/)
            console.log('    Funnel needs to be enabled on your tailnet:')
            console.log('    ' + (match ? match[0] : 'https://login.tailscale.com/admin/funnel'))
            console.log('    After enabling, press Enter to retry.')
            await ask('    Press Enter when enabled… ')
            ts('funnel --bg 3443', { stdio: 'inherit', timeout: 30000 })
          }
          console.log('  ✓ Tailscale Funnel active')
        } else {
          const ans2 = await ask('    Run tailscale serve --bg 3443 instead? (tailnet-only) (Y/n) ')
          if (ans2 !== 'n') {
            ts('serve --bg 3443', { stdio: 'inherit', timeout: 15000 })
            console.log('  ✓ Tailscale serve active')
          }
        }
      }
    }

    // ── Save Funnel URL to config.json ──
    const configPath = path.join(CFG, 'config.json')
    let config = readJson(configPath)
    if (funnelActive || ts('funnel status --json').includes(':3443') || ts('serve status --json').includes(':3443')) {
      try {
        const dnsName = (JSON.parse(ts('status --json')).Self?.DNSName || '').replace(/\.$/, '')
        if (dnsName) {
          config.serverOrigin = `https://${dnsName}`
          config.rpId = dnsName
          config.bindAddress = dnsName
          fs.mkdirSync(path.dirname(configPath), { recursive: true })
          fs.writeFileSync(configPath, JSON.stringify(config, null, 2))
          console.log('  ✓ config.json updated with Funnel URL: https://' + dnsName)
        }
      } catch {}
    }
  } else {
    console.log('  … Tailscale not installed')
    const ans = await ask('    Install Tailscale via winget? (Y/n) ')
    if (ans !== 'n') {
      console.log('    Installing Tailscale…')
      sh('winget install Tailscale.Tailscale', { stdio: 'inherit', timeout: 120000 })
      console.log('  ✓ Tailscale installed')
      console.log('  ⚠  Restart your terminal, then run:')
      console.log('      npm run setup')
      console.log('      (or: tailscale up && tailscale funnel --bg 3443)')
    } else {
      console.log('  ⚠  Without Tailscale, phone will see a TLS warning for self-signed certs')
      console.log('     Install manually: https://tailscale.com/download')
    }
  }

  // ── Summary ──
  console.log()
  console.log('  ' + '─'.repeat(40))
  console.log()
  const cfgPath = path.join(CFG, 'config.json')
  if (fs.existsSync(cfgPath)) {
    const cfg = readJson(cfgPath)
    console.log('  config.json: ' + cfgPath)
    if (cfg.serverOrigin) console.log('  URL:         ' + cfg.serverOrigin)
  } else {
    console.log('  ⚠  config.json not found')
    console.log('     Create it at ' + cfgPath)
  }
  console.log()
  console.log('  Run:  npm start')
  console.log()
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
