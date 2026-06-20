import type { PRFile } from '../rules'
import type { TrustBoundaryIntel, IntelRisk } from './types'

const SOURCE_PATTERNS = [
  /\breq\.(body|query|params|headers|cookies|signedCookies)/,
  /\brequest\.(body|query|params|headers|cookies)/,
  /\bevent\.(body|queryStringParameters|headers)/,
  /\bctx\.(body|query|params|headers)/,
  /\binput\b/,
  /\bargs\b/,
  /\bargv\b/,
  /\bprocess\.argv\b/,
  /\breadline\b/,
  /\bprompt\b/,
  /\bgetParameter\b/,
  /\bgetQueryString\b/,
  /\bgetHeader\b/,
  /\bform\.(get|parse)/,
  /\bmultipart\b/,
  /\brawBody\b/,
  /\bbodyParser\b/,
]

const SINK_PATTERNS = [
  /\bdb\.(query|execute|run|get|all|each)/,
  /\bsql\b/,
  /\bquery\s*\(/,
  /\bexecute\s*\(/,
  /\bfind\s*\(/,
  /\bfindOne\s*\(/,
  /\binsertOne\b/,
  /\binsertMany\b/,
  /\bupdateOne\b/,
  /\bupdateMany\b/,
  /\bdeleteOne\b/,
  /\bdeleteMany\b/,
  /\baggregate\b/,
  /\bexec\s*\(/,
  /\bspawn\s*\(/,
  /\beval\s*\(/,
  /\bFunction\s*\(/,
  /\bnew Function\b/,
  /\bfetch\s*\(/,
  /\baxios\b/,
  /\bhttp\.(get|post|request)\b/,
  /\bhttps\.(get|post|request)\b/,
  /\bwriteFileSync\b/,
  /\bwriteFile\b/,
  /\bappendFile\b/,
  /\bfs\.write\b/,
]

export function analyzeTrustBoundaries(files: PRFile[]): TrustBoundaryIntel | undefined {
  const flows: TrustBoundaryIntel['flows'] = []

  for (const file of files) {
    const patch = file.patch || ''
    const lines = patch.split('\n')
    let lineNum = 0
    const addedLines: { line: string; num: number }[] = []

    for (const line of lines) {
      lineNum++
      if (line.startsWith('+') && !line.startsWith('++')) {
        addedLines.push({ line: line.slice(1), num: lineNum })
      }
    }

    // Simple forward scan: look for source then sink within nearby lines
    for (let i = 0; i < addedLines.length; i++) {
      const current = addedLines[i]
      const isSource = SOURCE_PATTERNS.some(p => p.test(current.line))
      if (!isSource) continue

      // Look ahead up to 5 lines for a sink
      for (let j = i; j < Math.min(i + 6, addedLines.length); j++) {
        const candidate = addedLines[j]
        if (candidate === current) continue
        if (SINK_PATTERNS.some(p => p.test(candidate.line))) {
          const sourceMatch = current.line.match(/req|request|ctx|input|args|argv|event|body|query|param/i)
          const sinkMatch = candidate.line.match(/db|query|exec|eval|fetch|axios|http|writeFile|sql/i)
          flows.push({
            source: sourceMatch ? sourceMatch[0] : 'input',
            sink: sinkMatch ? sinkMatch[0] : 'sink',
            file: file.filename,
            line: current.num,
          })
          break
        }
      }
    }
  }

  if (flows.length === 0) return undefined

  let risk: IntelRisk = 'medium'
  const dangerousSinks = flows.filter(f =>
    /exec|spawn|eval|Function/.test(f.sink)
  )
  if (dangerousSinks.length > 0) risk = 'critical'
  else if (flows.length > 2) risk = 'high'

  return {
    summary: `${flows.length} trust boundary flow${flows.length > 1 ? 's' : ''}`,
    flows,
    risk,
  }
}
