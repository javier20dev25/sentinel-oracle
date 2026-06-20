import type { CIPolicy } from './types'

const DEFAULT_POLICY: CIPolicy = {
  expectedWorkflows: [],
  minJobs: 1,
  expectedJobs: [],
  maxDurationIncreasePct: 50,
  maxDurationDecreasePct: 30,
  requireArtifacts: false,
  sensitivePaths: ['.github/workflows/', 'package.json', 'requirements.txt', 'go.mod', 'Dockerfile', 'docker-compose.yml'],
  allowedRunners: ['ubuntu-latest', 'ubuntu-22.04', 'ubuntu-20.04', 'windows-latest', 'macos-latest'],
}

export function parsePolicy(raw: Record<string, any> | undefined | null): CIPolicy {
  if (!raw || !raw.sentinel) return { ...DEFAULT_POLICY }
  const p = raw.sentinel
  return {
    expectedWorkflows: Array.isArray(p.expected_workflows) ? p.expected_workflows : DEFAULT_POLICY.expectedWorkflows,
    minJobs: typeof p.min_jobs === 'number' ? p.min_jobs : DEFAULT_POLICY.minJobs,
    expectedJobs: Array.isArray(p.expected_jobs) ? p.expected_jobs : DEFAULT_POLICY.expectedJobs,
    expectedSteps: p.expected_steps || DEFAULT_POLICY.expectedSteps,
    maxDurationIncreasePct: typeof p.max_duration_increase_pct === 'number' ? p.max_duration_increase_pct : DEFAULT_POLICY.maxDurationIncreasePct,
    maxDurationDecreasePct: typeof p.max_duration_decrease_pct === 'number' ? p.max_duration_decrease_pct : DEFAULT_POLICY.maxDurationDecreasePct,
    requireArtifacts: !!p.require_artifacts,
    sensitivePaths: Array.isArray(p.sensitive_paths) ? p.sensitive_paths : DEFAULT_POLICY.sensitivePaths,
    allowedRunners: Array.isArray(p.allowed_runners) ? p.allowed_runners : DEFAULT_POLICY.allowedRunners,
  }
}

export function detectPolicyInFiles(files: { filename: string; patch?: string }[]): { policy?: CIPolicy; sourceFile?: string } {
  for (const f of files) {
    if (f.filename === 'sentinel.policy.yml' || f.filename === 'sentinel.policy.yaml') {
      try {
        // Simple YAML-like parser for the policy file
        const lines = (f.patch || '').split('\n').filter(l => !l.startsWith('-') && !l.startsWith('+') && !l.startsWith('diff') && !l.startsWith('@@'))
        const raw: Record<string, any> = {}
        let currentSection: string | null = null
        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed || trimmed.startsWith('#')) continue
          const sectionMatch = trimmed.match(/^(\w+):$/)
          if (sectionMatch) {
            currentSection = sectionMatch[1]
            raw[currentSection] = {}
            continue
          }
          const kvMatch = trimmed.match(/^  (\w[\w_]*):\s*(.+)$/)
          if (kvMatch && currentSection) {
            const val = kvMatch[2].trim()
            if (val === 'true') raw[currentSection][kvMatch[1]] = true
            else if (val === 'false') raw[currentSection][kvMatch[1]] = false
            else if (!isNaN(Number(val))) raw[currentSection][kvMatch[1]] = Number(val)
            else if (val.startsWith('[') && val.endsWith(']')) raw[currentSection][kvMatch[1]] = val.slice(1, -1).split(',').map((s: string) => s.trim().replace(/["']/g, ''))
            else if (val.startsWith('{')) {
              try { raw[currentSection][kvMatch[1]] = JSON.parse(val.replace(/'/g, '"')) } catch { raw[currentSection][kvMatch[1]] = val }
            } else raw[currentSection][kvMatch[1]] = val.replace(/["']/g, '')
          }
          // Also handle top-level list items
          const listMatch = trimmed.match(/^(\w[\w_]*):\s*$/)
          if (listMatch) {
            currentSection = listMatch[1]
            raw[currentSection] = {}
          }
        }
        const policy = parsePolicy(raw)
        if (policy) return { policy, sourceFile: f.filename }
      } catch {
        // If parsing fails, skip
      }
    }
  }
  return {}
}
