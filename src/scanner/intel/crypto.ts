import type { PRFile } from '../rules'
import type { CryptoIntel, IntelRisk } from './types'

interface ParamEntry { param: string; pattern: RegExp; extract: (line: string) => string | null }

const CRYPTO_PARAM_PATTERNS: ParamEntry[] = [
  { param: 'rounds', pattern: /(?:saltRounds|rounds|cost|workFactor)\s*[=:]\s*(\d+)/i, extract: line => { const m = line.match(/(?:saltRounds|rounds|cost|workFactor)\s*[=:]\s*(\d+)/i); return m ? m[1] : null } },
  { param: 'algorithm', pattern: /(?:algorithm|algo|method)\s*[=:]\s*['"`]?(\w+)['"`]?/i, extract: line => { const m = line.match(/(?:algorithm|algo|method)\s*[=:]\s*['"`]?(\w+)['"`]?/i); return m ? m[1] : null } },
  { param: 'keySize', pattern: /(?:keyLength|keySize|key[-_]?len|bitLength)\s*[=:]\s*(\d+)/i, extract: line => { const m = line.match(/(?:keyLength|keySize|key[-_]?len|bitLength)\s*[=:]\s*(\d+)/i); return m ? m[1] : null } },
  { param: 'expiry', pattern: /(?:expiresIn|expiration|exp|maxAge|ttl)\s*[=:]\s*(\d+)/i, extract: line => { const m = line.match(/(?:expiresIn|expiration|exp|maxAge|ttl)\s*[=:]\s*(\d+)/i); return m ? m[1] : null } },
  { param: 'issuer', pattern: /(?:issuer|iss)\s*[=:]\s*['"`](\w+)['"`]/i, extract: line => { const m = line.match(/(?:issuer|iss)\s*[=:]\s*['"`](\w+)['"`]/i); return m ? m[1] : null } },
  { param: 'audience', pattern: /(?:audience|aud)\s*[=:]\s*['"`](\w+)['"`]/i, extract: line => { const m = line.match(/(?:audience|aud)\s*[=:]\s*['"`](\w+)['"`]/i); return m ? m[1] : null } },
]

function buildImpact(param: string, before: string, after: string): string {
  switch (param) {
    case 'rounds': {
      const b = parseInt(before, 10)
      const a = parseInt(after, 10)
      if (isNaN(b) || isNaN(a)) return 'Changed hash rounds'
      if (a < (b || 10)) return `Reduced rounds from ${b} to ${a} — weaker hashing`
      return `Increased rounds from ${b || 'default'} to ${a} — stronger hashing`
    }
    case 'algorithm':
      if (/sha1|md5/i.test(after)) return `Downgrade to weak algorithm: ${after}`
      if (/sha256|sha512|bcrypt|argon/i.test(after)) return `Upgrade to strong algorithm: ${after}`
      return `Algorithm changed: ${before} → ${after}`
    case 'expiry':
      return `Token expiry changed: ${before} → ${after}`
    case 'keySize':
      return `Key size changed: ${before} → ${after}`
    default:
      return `Changed ${param}: ${before} → ${after}`
  }
}

export function analyzeCrypto(files: PRFile[]): CryptoIntel | undefined {
  const changes: CryptoIntel['changes'] = []

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')

    const removedLines: string[] = []
    const addedLines: string[] = []

    for (const line of lines) {
      if (line.startsWith('-') && !line.startsWith('--')) removedLines.push(line.slice(1))
      if (line.startsWith('+') && !line.startsWith('++')) addedLines.push(line.slice(1))
    }

    for (const entry of CRYPTO_PARAM_PATTERNS) {
      for (const addLine of addedLines) {
        const after = entry.extract(addLine)
        if (!after) continue

        let before = 'not set'
        for (const remLine of removedLines) {
          const beforeVal = entry.extract(remLine)
          if (beforeVal) {
            before = beforeVal
            break
          }
        }

        changes.push({
          parameter: entry.param,
          before,
          after,
          impact: buildImpact(entry.param, before, after),
        })
      }
    }
  }

  if (changes.length === 0) return undefined

  let risk: IntelRisk = 'low'
  const hasWeakness = changes.some(c =>
    /weak|downgrade|reduced/i.test(c.impact) || /sha1|md5/i.test(c.after)
  )
  if (hasWeakness) risk = 'critical'
  else if (changes.length > 0) risk = 'medium'

  return { summary: `${changes.length} crypto change${changes.length > 1 ? 's' : ''}`, changes, risk }
}
