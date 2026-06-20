import type { PRFile } from '../rules'
import type { AuthIntel, IntelRisk } from './types'

const ROUTE_PATTERNS = [
  /\brouter\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\bapp\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\bRoute::(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /@(Get|Post|Put|Delete|Patch|Options|Head)Mapping\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\b(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g,
]

const MIDDLEWARE_PATTERNS = [
  /\bapp\.use\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\brouter\.use\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\buse\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\b(app\.|router\.)?(auth|authenticate|authorize|requireAuth|protect|verifyToken|session|csrf|helmet|cors|rateLimit|bodyParser)\s*\(/gi,
]

function extractRoutes(lines: string[], isAdd: boolean): { path: string; method: string; file: string; line: number }[] {
  const routes: { path: string; method: string; file: string; line: number }[] = []
  for (let idx = 0; idx < lines.length; idx++) {
    for (const pattern of ROUTE_PATTERNS) {
      pattern.lastIndex = 0
      let match
      while ((match = pattern.exec(lines[idx])) !== null) {
        const method = match[1].toUpperCase()
        const path = match[2]
        routes.push({ path, method, file: '', line: idx + 1 })
      }
    }
  }
  return routes
}

function extractMiddlewareChanges(lines: string[], isAdd: boolean): { name: string; file: string; line: number }[] {
  const items: { name: string; file: string; line: number }[] = []
  for (let idx = 0; idx < lines.length; idx++) {
    for (const pattern of MIDDLEWARE_PATTERNS) {
      pattern.lastIndex = 0
      let match
      while ((match = pattern.exec(lines[idx])) !== null) {
        const name = match[1] || match[3] || match[4] || match[0]
        items.push({ name: name.replace(/['"`]/g, ''), file: '', line: idx + 1 })
      }
    }
  }
  return items
}

export function analyzeAuth(files: PRFile[]): AuthIntel | undefined {
  const newRoutes: AuthIntel['newRoutes'] = []
  const removedMiddleware: AuthIntel['removedMiddleware'] = []
  const changes: AuthIntel['changes'] = []

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')

    const addedLines: string[] = []
    const removedLines: string[] = []

    for (const line of lines) {
      if (line.startsWith('+') && !line.startsWith('++')) addedLines.push(line.slice(1))
      if (line.startsWith('-') && !line.startsWith('--')) removedLines.push(line.slice(1))
    }

    const addedRoutes = extractRoutes(addedLines, true)
    const removedRoutes = extractRoutes(removedLines, false)

    for (const r of addedRoutes) {
      r.file = file.filename
      newRoutes.push(r)
    }

    const addedMiddleware = extractMiddlewareChanges(addedLines, true)
    const removedMid = extractMiddlewareChanges(removedLines, false)

    // Check for removed middleware (auth middleware being removed)
    for (const mw of removedMid) {
      if (/auth|authenticate|protect|requireAuth|verifyToken|authorize|session/i.test(mw.name)) {
        mw.file = file.filename
        removedMiddleware.push(mw)
      }
    }

    // Check for auth-related changes
    for (const line of addedLines) {
      if (/skipAuth|bypass|disableAuth|noAuth|publicEndpoint|allowUnauthenticated|_skipAuth/i.test(line)) {
        changes.push({
          description: `Potential auth bypass: ${line.trim().substring(0, 80)}`,
          file: file.filename,
          line: addedLines.indexOf(line) + 1,
        })
      }
    }
  }

  if (newRoutes.length === 0 && removedMiddleware.length === 0 && changes.length === 0) return undefined

  let risk: IntelRisk = 'low'
  if (removedMiddleware.length > 0) risk = 'critical'
  else if (changes.some(c => /bypass|disable|skip|unauthenticated/i.test(c.description))) risk = 'critical'
  else if (newRoutes.length > 3) risk = 'medium'
  else if (newRoutes.length > 0) risk = 'low'

  return {
    summary: `${newRoutes.length} new route${newRoutes.length > 1 ? 's' : ''}${removedMiddleware.length > 0 ? ', middleware removed' : ''}${changes.length > 0 ? ', auth changes' : ''}`,
    newRoutes,
    removedMiddleware,
    changes,
    risk,
  }
}
