import type { InstructionManipulationAttempt } from './types'

const INJECTION_PATTERNS: { type: string; pattern: RegExp; severity: 'low' | 'medium' | 'high' | 'critical' }[] = [
  { type: 'instruction_override', pattern: /ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|prompts?)/i, severity: 'critical' },
  { type: 'instruction_override', pattern: /forget\s+(all\s+)?(your\s+)?(instructions|prompts?|training)/i, severity: 'critical' },
  { type: 'instruction_override', pattern: /disregard\s+(all\s+)?(previous|prior)\s+(instructions|prompts?)/i, severity: 'critical' },
  { type: 'role_redefinition', pattern: /you\s+are\s+(now\s+)?(not\s+)?(sentinel|an?\s+ai|coder?|assistant)/i, severity: 'high' },
  { type: 'role_redefinition', pattern: /from\s+now\s+on\s*,\s*you\s+are/i, severity: 'high' },
  { type: 'role_redefinition', pattern: /act\s+as\s+(if\s+you\s+are|an?\s+ai)/i, severity: 'medium' },
  { type: 'suppression', pattern: /do\s+(not|n't)\s+(report|mention|tell|say|flag|note|document)/i, severity: 'critical' },
  { type: 'suppression', pattern: /(do\s+not|never)\s+(show|display|output|reveal|include)\s+(this|the|any)/i, severity: 'high' },
  { type: 'suppression', pattern: /if\s+(asked|questioned|queried)\s+(about|regarding)/i, severity: 'high' },
  { type: 'hidden_instruction', pattern: /<!--.*?(ignore|forget|disregard|override).*?-->/is, severity: 'high' },
  { type: 'hidden_instruction', pattern: /\/\/\s*(TODO|FIXME|HACK|XXX).*?(ignore|forget|ai|review)/i, severity: 'medium' },
  { type: 'config_manipulation', pattern: /\.opencode\//, severity: 'critical' },
  { type: 'config_manipulation', pattern: /AGENTS\.md/i, severity: 'critical' },
  { type: 'config_manipulation', pattern: /prompts?\s*:.*?(ignore|skip|bypass)/i, severity: 'high' },
  { type: 'encoded_instruction', pattern: /(ZXZhb|YmFzZTY0|cHJvbXB0|aWdu|b3ZlcnJp)/i, severity: 'medium' },
]

export function detectInstructionManipulation(
  files: { filename: string; patch?: string; status: string }[]
): InstructionManipulationAttempt[] {
  const attempts: InstructionManipulationAttempt[] = []

  for (const file of files) {
    if (!file.patch) continue
    const lines = file.patch.split('\n')

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      for (const { type, pattern, severity } of INJECTION_PATTERNS) {
        const match = line.match(pattern)
        if (match) {
          const snippet = line.substring(Math.max(0, match.index! - 20), match.index! + match[0].length + 30).trim()
          attempts.push({
            type,
            description: `Potential ${type.replace(/_/g, ' ')} detected`,
            evidence: { file: file.filename, line: i + 1, snippet },
            severity,
          })
        }
      }
    }

    if (file.patch.length > 100 && (file.filename.endsWith('.md') || file.filename === 'AGENTS.md' || file.filename.startsWith('.opencode'))) {
      attempts.push({
        type: 'config_manipulation',
        description: `Suspicious large change to AI-related file: ${file.filename}`,
        evidence: { file: file.filename, line: 1, snippet: `${file.patch.length} bytes changed` },
        severity: 'high',
      })
    }
  }

  return attempts
}

export function hasInstructionManipulation(attempts: InstructionManipulationAttempt[]): boolean {
  return attempts.some(a => a.severity === 'critical' || a.severity === 'high')
}
