import * as readline from 'readline'
import * as fs from 'fs'
import * as path from 'path'
import { saveConfig } from './config'

const CYAN = '\x1b[38;2;50;200;255m'
const GREEN = '\x1b[38;2;50;255;120m'
const YLW = '\x1b[38;2;255;200;0m'
const RED = '\x1b[38;2;255;70;70m'
const BLD = '\x1b[1m'
const DIM = '\x1b[2m'
const R = '\x1b[0m'
const CLS = '\x1b[2J\x1b[H'
const ORG = '\x1b[38;2;255;165;0m'

const divider = ` ${DIM}────────────────────────────────────────────${R}`

function tokenUrl(owner?: string): string {
  const params: string[] = []
  params.push('name=sentinel-oracle')
  params.push('description=Sentinel+Oracle+Server')
  params.push('pull_requests=write')
  params.push('contents=read')
  if (owner) params.push(`target_name=${encodeURIComponent(owner)}`)
  return 'https://github.com/settings/personal-access-tokens/new?' + params.join('&')
}

function ask(rl: readline.Interface, question: string): Promise<string> {
  return new Promise(resolve => rl.question(question, resolve))
}

function showAnimation(): void {
  const frames = ['◴', '◷', '◶', '◵']
  let i = 0
  const interval = setInterval(() => {
    process.stdout.write(`\r ${CYAN}${frames[i]}${R} ${DIM}Initializing...${R}`)
    i = (i + 1) % frames.length
  }, 120)
  setTimeout(() => {
    clearInterval(interval)
    process.stdout.write(`\r ${GREEN}●${R} ${DIM}Ready${R}\n`)
  }, 1500)
}

async function promptPat(owner?: string): Promise<string | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })

  return new Promise(resolve => {
    process.stdout.write(CLS)
    console.log(` ${BLD}${CYAN}Sentinel Oracle${R} ${DIM}— First-Time Setup${R}`)
    console.log()
    console.log(` ${YLW}No valid GitHub token found.${R}`)
    console.log()
    console.log(` Create a ${BLD}fine-grained PAT${R} ${DIM}(not classic)${R} at GitHub:`)
    console.log()
    console.log(` ${BLD}Required permissions:${R}`)
    console.log(`   ${GREEN}•${R} Pull requests — ${BLD}Write${R}     ${DIM}(approve & merge PRs, write commit status)${R}`)
    console.log(`   ${GREEN}•${R} Contents     — ${BLD}Read${R}      ${DIM}(read repository contents)${R}`)
    console.log(`   ${GREEN}•${R} Metadata     — ${BLD}Read${R}      ${DIM}(read repository metadata)${R}`)
    console.log()
    console.log(` ${BLD}Repository access:${R} ${DIM}Only select repositories → pick your repo${R}`)
    console.log()
    const url = tokenUrl(owner)
    console.log(` ${DIM}Pre-filled link (click, check permissions, generate):${R}`)
    console.log(` ${CYAN}${url}${R}`)
    console.log()
    console.log(` ${DIM}(Press Ctrl+C to skip and start in setup mode)${R}`)
    console.log()

    rl.question(` ${BLD}Paste the token${R} ${DIM}(starts with github_pat_...)${R}: `, answer => {
      rl.close()
      const token = answer.trim()
      if (!token) { resolve(null); return }
      resolve(token)
    })
  })
}

async function promptGithubApp(): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise(resolve => {
    rl.question(` ${BLD}Configure GitHub App?${R} ${DIM}(optional, y/N)${R}: `, answer => {
      rl.close()
      resolve(answer.trim().toLowerCase() === 'y')
    })
  })
}

async function collectGithubApp(): Promise<{ appId: string; installationId: string; privateKey: string } | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  try {
    console.log()
    console.log(` ${BLD}${YLW}GitHub App Setup (optional)${R}`)
    console.log()
    console.log(` ${DIM}If you already have a GitHub App installed, paste:`)
    console.log(`   ${GREEN}•${R} App ID           ${DIM}→ Settings → GitHub Apps → Edit → About → App ID${R}`)
    console.log(`   ${GREEN}•${R} Installation ID  ${DIM}→ Settings → Installed GitHub Apps → Configure → URL number${R}`)
    console.log(`   ${GREEN}•${R} Private key path ${DIM}→ the .pem file you downloaded${R}`)
    console.log()
    console.log(` ${DIM}If not, create one at ${CYAN}https://github.com/settings/apps/new${R}`)
    console.log(` ${DIM}  • Webhook: Active → URL: https://example.com (change later)`)
    console.log(` ${DIM}  • Repository permissions → Pull requests: Read & Write`)
    console.log(` ${DIM}  • After creating → Generate a private key → Download .pem`)
    console.log(` ${DIM}  • Then install the app on your repository`)
    console.log()
    console.log(` ${DIM}(Press Ctrl+C to skip GitHub App setup)${R}`)
    console.log()

    const appId = (await ask(rl, ` ${BLD}App ID${R} ${DIM}(e.g. 4039818)${R}: `)).trim()
    if (!appId) { return null }
    if (!/^\d+$/.test(appId)) {
      console.log(` ${RED}Invalid App ID — must be a number (e.g. 4039818). Skipping GitHub App setup.${R}`)
      console.log()
      return null
    }

    const installationId = (await ask(rl, ` ${BLD}Installation ID${R} ${DIM}(e.g. 139924356)${R}: `)).trim()
    if (!installationId) { return null }
    if (!/^\d+$/.test(installationId)) {
      console.log(` ${RED}Invalid Installation ID — must be a number. Skipping GitHub App setup.${R}`)
      console.log()
      return null
    }

    const keyPath = (await ask(rl, ` ${BLD}Private key path${R} ${DIM}(e.g. C:\\keys\\app.pem)${R}: `)).trim()
    if (!keyPath) { return null }
    if (!fs.existsSync(keyPath)) {
      console.log(` ${RED}File not found: ${keyPath}. Skipping GitHub App setup.${R}`)
      console.log()
      return null
    }

    let privateKey: string
    try {
      privateKey = fs.readFileSync(keyPath, 'utf8')
    } catch {
      console.log(` ${RED}Could not read file: ${keyPath}${R}`)
      return null
    }
    if (!privateKey.includes('BEGIN PRIVATE KEY')) {
      console.log(` ${RED}File is not a valid PEM private key${R}`)
      return null
    }

    console.log(` ${GREEN}✓ Private key loaded (${privateKey.length} bytes)${R}`)

    return { appId, installationId, privateKey }
  } finally {
    rl.close()
  }
}

function savePrivateKey(key: string): string {
  const dir = path.join(require('os').homedir(), '.sentinel-oracle')
  const keyPath = path.join(dir, 'github-app-private-key.pem')
  fs.writeFileSync(keyPath, key, { mode: 0o600 })
  return keyPath
}

export async function runSetupWizard(owner?: string, repo?: string): Promise<{ token: string } | null> {
  const token = await promptPat(owner)
  if (!token) {
    console.log()
    console.log(` ${YLW}No token provided — skipping setup.${R}`)
    console.log(` ${DIM}Start the server and configure via the Web UI.${R}`)
    console.log()
    return null
  }

  console.log()
  console.log(` ${DIM}Testing token against GitHub API...${R}`)

  try {
    const controller = new AbortController()
    const id = setTimeout(() => controller.abort(), 5000)
    const res = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'sentinel-oracle' },
      signal: controller.signal,
    })
    clearTimeout(id)
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      console.log(` ${RED}Token rejected (HTTP ${res.status})${R}`)
      if (text) console.log(` ${DIM}${text.slice(0, 200)}${R}`)
      console.log(` ${DIM}Make sure it's a fine-grained PAT with pull_requests:write.${R}`)
      console.log()
      return null
    }
  } catch (e: any) {
    if (e?.name === 'AbortError') {
      console.log(` ${RED}Request timed out — check internet connection.${R}`)
    } else {
      console.log(` ${RED}Verification failed: ${e?.message || e}${R}`)
    }
    console.log(` ${DIM}Set SENTINEL_SKIP_TOKEN_VERIFY=1 to skip verification.${R}`)
    console.log()
    return null
  }

  console.log(` ${GREEN}✓ Token verified${R}`)
  saveConfig({ githubToken: token })
  console.log(` ${GREEN}✓ Saved to config.json${R}`)
  console.log()

  const wantsApp = await promptGithubApp()
  if (wantsApp) {
    const app = await collectGithubApp()
    if (app) {
      const keyPath = savePrivateKey(app.privateKey)
      saveConfig({
        githubAppId: app.appId,
        githubInstallationId: app.installationId,
        githubPrivateKeyPath: keyPath,
      })
      console.log(` ${GREEN}✓ GitHub App configured${R}`)
    }
  }

  console.log()
  console.log(divider)
  console.log(` ${GREEN}${BLD}  All set! Starting server...${R}`)
  console.log(divider)
  console.log()
  showAnimation()
  console.log()

  return { token }
}
