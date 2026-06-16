import QRCode from 'qrcode'
import type { Config } from './config'
import type { DatabaseStore } from './storage/database'
import { getEnrollmentToken } from './server'

const R = '\x1b[0m'
const BLD = '\x1b[1m'
const DIM = '\x1b[2m'
const CLS = '\x1b[2J\x1b[H'

const CYAN = '\x1b[38;2;50;200;255m'
const GREEN = '\x1b[38;2;50;255;120m'
const GRY = '\x1b[38;2;100;100;100m'
const BLU = '\x1b[38;2;80;80;180m'

export async function printStartupBanner(config: Config, db: DatabaseStore): Promise<void> {
  const devCount = db.listDevices().length
  const locked = db.getConfig('system_lockdown') === 'true'
  const token = getEnrollmentToken()
  const enrolled = db.getConfig('enrollment_completed') === 'true'
  const url = config.serverOrigin

  let qrLines: string[] = []
  const enrollUrl = !enrolled && token ? `${url}/?enroll=${token}` : url
  try {
    const raw: string = await (QRCode as any).toString(enrollUrl, { type: 'utf8', small: true })
    qrLines = raw.split('\n').filter(l => l.trim())
  } catch {}

  process.stdout.write(CLS)

  // Title
  console.log(` ${BLD}${CYAN}Sentinel Oracle${R} ${GRY}v1.0.0${R}`)
  console.log(` ${GRY}Secure Merge Authorization Server${R}`)
  console.log()

  // Info
  console.log(` ${GREEN}${url}${R}`)
  console.log(` ${DIM}RP ID: ${config.rpId}${R}`)
  console.log(` ${DIM}Devices: ${devCount} registered | Lock: ${locked ? '\x1b[38;2;255;70;70m● Active' : GREEN + '○ Inactive'}${R}`)
  console.log()

  // Enrollment status
  if (!enrolled && token) {
    console.log(` ${BLD}First-time setup token configured (length: ${token.length})${R}`)
    console.log(` ${DIM}POST /api/setup/begin with this token to enroll${R}`)
  } else {
    console.log(` ${GREEN}Enrollment complete${R}${DIM} — register new devices from the dashboard${R}`)
  }
  if (locked) {
    console.log(` ${BLD}\x1b[38;2;255;70;70mSystem in lockdown${R}${DIM} — POST /api/unlock to deactivate${R}`)
  }
  if (!config.githubWebhookSecret) {
    console.log(` \x1b[38;2;255;200;0m⚠ Webhook secret not configured${R}${DIM} — set githubWebhookSecret in config.json to verify incoming webhooks${R}`)
  }
  if (!config.scanEnabled) {
    console.log(` \x1b[38;2;255;200;0m💡 PR scanning is disabled${R}${DIM} — set "scanEnabled": true in config.json to enable code analysis${R}`)
  }
  console.log()

  // QR code
  if (qrLines.length > 0) {
    for (const l of qrLines) {
      console.log(' ' + l)
    }
    console.log(` ${GRY}Scan to open: ${enrollUrl}${R}`)
    console.log()
  }
}
