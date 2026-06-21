import * as readline from 'readline'
import { saveConfig } from './config'

const CYAN = '\x1b[38;2;50;200;255m'
const GREEN = '\x1b[38;2;50;255;120m'
const YLW = '\x1b[38;2;255;200;0m'
const RED = '\x1b[38;2;255;70;70m'
const BLD = '\x1b[1m'
const DIM = '\x1b[2m'
const R = '\x1b[0m'
const CLS = '\x1b[2J\x1b[H'

function tokenUrl(owner?: string, _repo?: string): string {
  const params: string[] = []
  params.push('name=sentinel-oracle')
  params.push('description=Sentinel+Oracle+Server')
  params.push('pull_requests=write')
  params.push('contents=read')
  if (owner) params.push(`target_name=${encodeURIComponent(owner)}`)
  return 'https://github.com/settings/personal-access-tokens/new?' + params.join('&')
}

function promptToken(owner?: string, repo?: string): Promise<string | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })

  return new Promise(resolve => {
    process.stdout.write(CLS)
    console.log(` ${BLD}${CYAN}Sentinel Oracle${R} ${DIM}— First-Time Setup${R}`)
    console.log()
    console.log(` ${YLW}No valid GitHub token found.${R}`)
    console.log()
    console.log(` Create a ${BLD}fine-grained PAT${R} with these permissions:`)
    console.log(`   ${GREEN}•${R} Pull requests: ${BLD}Write${R}  (to merge PRs and write commit status)`)
    console.log()
    const url = tokenUrl(owner, repo)
    console.log(` ${DIM}Open this URL in your browser:${R}`)
    console.log(` ${CYAN}${url}${R}`)
    console.log()
    if (owner && repo) {
      console.log(` ${DIM}The owner/repo fields should be pre-filled.${R}`)
    }
    console.log(` ${DIM}Select only the repository you want to protect.${R}`)
    console.log(` ${DIM}Generate the token and paste it below.${R}`)
    console.log()
    console.log(` ${DIM}(Press Ctrl+C to skip and start in setup mode)${R}`)
    console.log()

    rl.question(` ${BLD}Paste your fine-grained PAT:${R} `, answer => {
      rl.close()
      const token = answer.trim()
      if (!token) {
        resolve(null)
        return
      }
      resolve(token)
    })
  })
}

export async function runSetupWizard(owner?: string, repo?: string): Promise<{ token: string } | null> {
  const token = await promptToken(owner, repo)
  if (!token) {
    console.log()
    console.log(` ${YLW}No token provided — skipping setup.${R}`)
    console.log(` ${DIM}Start the server and configure via the Web UI,${R}`)
    console.log(` ${DIM}or run again when you have a token ready.${R}`)
    console.log()
    return null
  }

  console.log()
  console.log(` ${DIM}Testing token...${R}`)

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
      console.log(` ${RED}Token rejected by GitHub (HTTP ${res.status})${R}`)
      if (text) console.log(` ${DIM}${text.slice(0, 200)}${R}`)
      console.log(` ${DIM}Check the permissions and try again.${R}`)
      console.log()
      return null
    }
  } catch (e: any) {
    if (e?.name === 'AbortError') {
      console.log(` ${RED}Request timed out — check your internet connection.${R}`)
    } else {
      console.log(` ${RED}Could not verify token: ${e?.message || e}${R}`)
    }
    console.log(` ${DIM}Token not saved. Try again or use SENTINEL_SKIP_TOKEN_VERIFY=1.${R}`)
    console.log()
    return null
  }

  console.log(` ${GREEN}Token verified successfully.${R}`)
  console.log(` ${DIM}Saving to config...${R}`)

  saveConfig({ githubToken: token })
  console.log(` ${GREEN}Saved to ~/.sentinel-oracle/config.json${R}`)
  console.log()
  console.log(` ${BLD}Restart the server and it will use this token.${R}`)
  console.log()

  return { token }
}
