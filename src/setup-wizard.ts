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
    console.log(` ${BLD}${YLW}GitHub App Setup${R}`)
    console.log(` ${DIM}Create a GitHub App at:${R}`)
    console.log(` ${CYAN}https://github.com/settings/apps/new${R}`)
    console.log(` ${DIM}• Webhook: Active → URL: https://example.com (change later)${R}`)
    console.log(` ${DIM}• Permissions → Pull requests: Read & Write${R}`)
    console.log(` ${DIM}• Generate a private key after creating the app${R}`)
    console.log(` ${DIM}• Install the app on your repository${R}`)
    console.log(` ${DIM}  → Copy the Installation ID from the URL${R}`)
    console.log()
    console.log(` ${DIM}(Or press Ctrl+C to skip)${R}`)
    console.log()

    const appId = (await ask(rl, ` ${BLD}App ID${R}: `)).trim()
    if (!appId) { return null }

    const installationId = (await ask(rl, ` ${BLD}Installation ID${R}: `)).trim()
    if (!installationId) { return null }

    console.log(` ${DIM}Paste the full private key (PEM), then press Enter twice:${R}`)
    console.log()
    const lines: string[] = []
    while (true) {
      const line = (await ask(rl, ` ${DIM}>${R} `))
      if (line.trim() === '' && lines.length > 0 && lines[lines.length - 1].trim() === '') break
      lines.push(line)
    }
    const privateKey = lines.join('\n').trim()
    if (!privateKey || !privateKey.includes('BEGIN PRIVATE KEY')) {
      console.log(` ${RED}Invalid private key — skipping GitHub App setup.${R}`)
      return null
    }

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
