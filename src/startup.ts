import QRCode from 'qrcode'
import type { Config } from './config'
import type { DatabaseStore } from './storage/database'
import { getEnrollmentToken } from './server'
import { execSync } from 'child_process'
import * as fs from 'fs'

const R = '\x1b[0m'
const BLD = '\x1b[1m'
const DIM = '\x1b[2m'
const CLS = '\x1b[2J\x1b[H'

const CYAN = '\x1b[38;2;50;200;255m'
const GREEN = '\x1b[38;2;50;255;120m'
const GRY = '\x1b[38;2;100;100;100m'
const YLW = '\x1b[38;2;255;200;0m'
const RED = '\x1b[38;2;255;70;70m'

interface HealthCheck {
  label: string
  ok: boolean
  detail: string
  fix?: string
}

function tailscaleBin(): string {
  if (process.platform === 'win32') {
    const winPath = 'C:\\Program Files\\Tailscale\\tailscale.exe'
    if (fs.existsSync(winPath)) return winPath
  }
  return 'tailscale'
}

function checkTailscale(): HealthCheck[] {
  const checks: HealthCheck[] = []
  try {
    const out = execSync(`"${tailscaleBin()}" status --json`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
    const status = JSON.parse(out)
    const self = status.Self || {}
    const online = self.Online === true
    const dnsName = (self.DNSName || '').replace(/\.$/, '')
    const ip = (self.TailscaleIPs || [])[0] || ''

    checks.push({
      label: 'Tailscale connected',
      ok: online,
      detail: online ? `${dnsName || ip}` : 'Tailscale is not connected',
      fix: online ? undefined : 'Run "tailscale up" to connect to your tailnet',
    })

    if (online && dnsName) {
      checks.push({
        label: 'MagicDNS enabled',
        ok: !!dnsName,
        detail: dnsName,
        fix: dnsName ? undefined : 'Enable MagicDNS in Tailscale admin console (DNS → MagicDNS)',
      })

      const funnelOut = execSync(`"${tailscaleBin()}" funnel status --json`, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })
      const funnelCfg = JSON.parse(funnelOut)
      const web = funnelCfg.Web || {}
      const hasFunnel = Object.keys(web).some(k => {
        const handlers = web[k]?.Handlers || {}
        return Object.values(handlers).some((h: any) => (h.Proxy || '').includes(':3443'))
      })

      checks.push({
        label: 'Tailscale Funnel',
        ok: hasFunnel,
        detail: hasFunnel ? `https://${dnsName} → localhost:3443` : 'Not configured',
        fix: hasFunnel ? undefined : `Run: "${tailscaleBin()}" funnel --https=443 localhost://3443`,
      })
    }
  } catch {
    checks.push({
      label: 'Tailscale',
      ok: false,
      detail: 'Could not query Tailscale status',
      fix: 'Install Tailscale from https://tailscale.com/download',
    })
  }
  return checks
}

async function checkGithub(): Promise<HealthCheck[]> {
  const checks: HealthCheck[] = []
  try {
    const controller = new AbortController()
    const id = setTimeout(() => controller.abort(), 3000)
    const res = await fetch('https://api.github.com', { signal: controller.signal, method: 'HEAD' })
    clearTimeout(id)
    checks.push({
      label: 'GitHub API reachable',
      ok: true,
      detail: `HTTP ${res.status}`,
    })
  } catch (e: any) {
    const msg = e?.cause?.code || e?.code || e?.message || 'timeout'
    checks.push({
      label: 'GitHub API reachable',
      ok: false,
      detail: msg === 'timeout' || e?.name === 'AbortError' ? 'Connection timed out (3s)' : msg,
      fix: '❯ Run: tailscale set --accept-dns=false && ipconfig /flushdns',
    })
  }
  return checks
}

function checkGitHubConfig(config: Config): HealthCheck[] {
  const checks: HealthCheck[] = []
  const hasToken = !!config.githubToken
  const hasApp = !!config.githubAppId && !!config.githubInstallationId && !!config.githubPrivateKeyPath

  if (!hasToken && !hasApp) {
    checks.push({
      label: 'GitHub credentials',
      ok: false,
      detail: 'No GitHub token or App configured',
      fix: '❯ Configure via /setup or set githubToken in config.json',
    })
  }

  if (!config.githubOwner || !config.githubRepo) {
    checks.push({
      label: 'GitHub repo',
      ok: false,
      detail: `owner="${config.githubOwner || ''}" repo="${config.githubRepo || ''}"`,
      fix: '❯ Set githubOwner and githubRepo in config.json',
    })
  }

  return checks
}

export function printBanner(config: Config, db: DatabaseStore): void {
  const devCount = db.listDevices().length
  const locked = db.getConfig('system_lockdown') === 'true'
  const token = getEnrollmentToken()
  const enrolled = db.getConfig('enrollment_completed') === 'true'
  const url = config.serverOrigin

  process.stdout.write(CLS)

  console.log(` ${BLD}${CYAN}Sentinel Oracle${R} ${GRY}v1.0.0${R}`)
  console.log(` ${GRY}Secure Merge Authorization Server${R}`)
  console.log()
  console.log(` ${GREEN}${url}${R}`)
  console.log(` ${DIM}RP ID: ${config.rpId}${R}`)
  console.log(` ${DIM}Devices: ${devCount} registered | Lock: ${locked ? `${RED}● Active` : `${GREEN}○ Inactive`}${R}`)
  console.log()

  if (!enrolled && token) {
    console.log(` ${BLD}First-time setup token configured (length: ${token.length})${R}`)
    console.log(` ${DIM}POST /api/setup/begin with this token to enroll${R}`)
  } else {
    console.log(` ${GREEN}Enrollment complete${R}${DIM} — register new devices from the dashboard${R}`)
  }
  if (locked) {
    console.log(` ${BLD}${RED}System in lockdown${R}${DIM} — POST /api/unlock to deactivate${R}`)
  }
  if (!config.githubWebhookSecret) {
    console.log(` ${YLW}⚠ Webhook secret not configured${R}${DIM} — set githubWebhookSecret in config.json to verify incoming webhooks${R}`)
  }
  if (!config.scanEnabled) {
    console.log(` ${YLW}💡 PR scanning is disabled${R}${DIM} — set "scanEnabled": true in config.json to enable code analysis${R}`)
  }
  console.log()

  // QR code (generated in background, prints when ready)
  const qrUrl: string = !enrolled && token ? `${url}/?enroll=${token}` : url
  ;(QRCode.toString as Function)(qrUrl, { type: 'utf8', small: true }).then((raw: string) => {
    const lines = raw.split('\n').filter(l => l.trim())
    for (const l of lines) {
      console.log(' ' + l)
    }
    console.log(` ${GRY}Scan to open: ${qrUrl}${R}`)
    console.log()
  }).catch(() => {})
}

export async function printHealthSummary(config: Config): Promise<void> {
  const healthChecks: HealthCheck[] = [
    ...checkTailscale(),
    ...await checkGithub(),
    ...checkGitHubConfig(config),
  ]

  const errors = healthChecks.filter(c => !c.ok)
  const warnings = healthChecks.filter(c => c.ok && c.fix)

  if (errors.length > 0 || warnings.length > 0) {
    console.log(` ${BLD}${YLW}── Health ──────────────────────────────────────${R}`)

    for (const c of healthChecks) {
      const icon = c.ok ? `${GREEN}✓${R}` : `${RED}✗${R}`
      console.log(` ${icon} ${BLD}${c.label}${R}${c.ok ? ` ${GRY}—${R} ${c.detail}` : ''}`)
      if (!c.ok && c.detail) {
        console.log(`   ${DIM}${c.detail}${R}`)
      }
      if (c.fix) {
        console.log(`   ${c.fix}${R}`)
      }
    }

    console.log()
    console.log(` ${errors.length > 0 ? RED : YLW}${errors.length} error(s)${R}${warnings.length > 0 ? `, ${YLW}${warnings.length} warning(s)${R}` : ''} ${GRY}— see above for fixes${R}`)
    console.log()
  }
}