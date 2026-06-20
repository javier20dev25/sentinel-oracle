import type { PRFile } from '../rules'
import type { EndpointIntel, IntelRisk } from './types'

const KNOWN_DOMAINS = new Set([
  'api.github.com', 'github.com', 'raw.githubusercontent.com',
  'api.stripe.com', 'stripe.com',
  'sentry.io', 'sentry.example.com',
  'auth.example.com',
  'api.openai.com', 'openai.com',
  'api.anthropic.com', 'anthropic.com',
  'api.posthog.com', 'posthog.com',
  'api.resend.com', 'resend.com',
  'api.sendgrid.com', 'sendgrid.com',
  'api.twilio.com', 'twilio.com',
  'api.discord.com', 'discord.com',
  'api.slack.com', 'slack.com',
  'api.telegram.org',
  'googleapis.com', 'api.google.com',
  'aws.amazon.com', 'amazonaws.com',
  'api.cloudflare.com', 'cloudflare.com',
  'api.datadoghq.com', 'datadoghq.com',
  'api.newrelic.com', 'newrelic.com',
  'api.mixpanel.com', 'mixpanel.com',
  'api.segment.io', 'segment.io',
  'api.logz.io',
  'docker.io', 'docker.com',
  'npmjs.org', 'npmjs.com',
  'registry.npmjs.org',
  'pypi.org', 'pypi.python.org',
  'crates.io',
  'proxy.golang.org',
  'repo1.maven.org',
  'maven.org',
])

const SUSPICIOUS_TLDS = new Set(['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.bid', '.cam'])

function isIpAddress(s: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(s)
}

function extractUrl(line: string): string[] {
  const urls: string[] = []
  const urlRegex = /https?:\/\/[^\s"'>)]+/g
  let match
  while ((match = urlRegex.exec(line)) !== null) {
    urls.push(match[0].replace(/[,.]+$/, ''))
  }
  return urls
}

export function analyzeEndpoints(files: PRFile[]): EndpointIntel | undefined {
  const added: EndpointIntel['added'] = []
  const suspicious: EndpointIntel['suspicious'] = []
  let lineNum = 0

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')
    lineNum = 0
    for (const line of lines) {
      lineNum++
      if (!line.startsWith('+')) continue
      const urls = extractUrl(line)
      for (const url of urls) {
        let host: string
        try { host = new URL(url).hostname } catch { host = url.split('/')[2] || url }
        added.push({ url, file: file.filename, line: lineNum })

        if (KNOWN_DOMAINS.has(host)) continue

        const reasons: string[] = []
        if (isIpAddress(host)) reasons.push('IP address literal')
        if (SUSPICIOUS_TLDS.has('.' + host.split('.').slice(-2).join('.'))) reasons.push('Suspicious TLD')
        if ([...SUSPICIOUS_TLDS].some(t => host.endsWith(t))) reasons.push('Suspicious TLD')

        const sld = host.split('.').slice(-2).join('.')
        if (SUSPICIOUS_TLDS.has('.' + sld)) reasons.push('Suspicious TLD')

        if (!KNOWN_DOMAINS.has(host) && !host.includes('.') && host !== 'localhost') {
          reasons.push('Unrecognized hostname')
        }

        if (reasons.length > 0) {
          suspicious.push({ url, reason: reasons.join(', '), file: file.filename, line: lineNum })
        }
      }
    }
  }

  if (added.length === 0) return undefined

  let risk: IntelRisk = 'low'
  if (suspicious.length > 0) risk = 'high'

  return {
    summary: `${added.length} new endpoint${added.length > 1 ? 's' : ''}${suspicious.length > 0 ? ` (${suspicious.length} suspicious)` : ''}`,
    added, removed: [], suspicious, risk,
  }
}
