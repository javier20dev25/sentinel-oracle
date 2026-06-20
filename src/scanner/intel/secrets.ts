import type { PRFile } from '../rules'
import type { SecretSurfaceIntel, IntelRisk } from './types'

const ENV_SOURCE_PATTERNS = [
  /\bprocess\.env\.(\w+)/g,
  /\benv\.(\w+)/g,
  /\bprocess\.env\[['"`](\w+)['"`]\]/g,
  /\bos\.environ(?:\[['"](\w+)['"]\])/g,
  /os\.Getenv\(['"`](\w+)['"`]\)/g,
  /\$_ENV\['(\w+)'\]/g,
  /\.env\.(\w+)/g,
  /env\(['"`](\w+)['"`]\)/g,
  /environ\[['"`](\w+)['"`]\]/g,
  /System\.getenv\(['"`](\w+)['"`]\)/g,
  /getenv\(['"`](\w+)['"`]\)/g,
]

const SENSITIVE_VAR_PATTERNS = [
  /(api[_-]?key|apikey|secret|token|password|passwd|credential|auth|jwt|session|private[_-]?key)/i,
]

const CONSUMER_PATTERNS = [
  /\bprocess\.env\.(\w+)/g,
  /\benv\.(\w+)/g,
  /\bprocess\.env\[['"`](\w+)['"`]\]/g,
  /\benv\(['"`](\w+)['"`]\)/g,
]

export function analyzeSecrets(files: PRFile[]): SecretSurfaceIntel | undefined {
  const sources: SecretSurfaceIntel['sources'] = []
  const consumers: SecretSurfaceIntel['consumers'] = []

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')
    let lineNum = 0

    for (const line of lines) {
      lineNum++
      if (!line.startsWith('+')) continue
      const content = line.slice(1)

      // Find env var usages
      for (const pattern of ENV_SOURCE_PATTERNS) {
        pattern.lastIndex = 0
        let match
        while ((match = pattern.exec(content)) !== null) {
          const varName = match[1]
          if (SENSITIVE_VAR_PATTERNS.some(p => p.test(varName))) {
            sources.push({ var: varName, file: file.filename, line: lineNum })
          }
          // Track all env var usage as consumers (where the value is used)
          consumers.push({ var: varName, file: file.filename, line: lineNum })
        }
      }
    }
  }

  if (sources.length === 0 && consumers.length === 0) return undefined

  let risk: IntelRisk = 'low'
  if (sources.length > 0) risk = 'medium'
  const hasCritical = sources.some(s =>
    /secret|password|private_key|token|jwt/i.test(s.var)
  )
  if (hasCritical) risk = 'high'
  if (risk === 'high' && sources.length > 3) risk = 'critical'

  return {
    summary: `${sources.length} sensitive var${sources.length > 1 ? 's' : ''} accessed, ${consumers.length} total usage${consumers.length > 1 ? 's' : ''}`,
    sources,
    consumers,
    risk,
  }
}
