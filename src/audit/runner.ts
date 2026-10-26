import { execFile } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)
const SHA_RE = /^[a-f0-9]{40}$/i

export interface SentinelAuditRun {
  commitSha: string
  executionId: string
  pipelineStatus: string
  verdict: string
  analysisState: string
  canClaimClean: boolean
  candidates: Array<{ id: string; severity: string; file?: string; line?: number; summary: string; evidence: Array<{ tool: string; rule: string; line?: number; detail: string }> }>
  tools: Array<{ name: string; status: string; verdict: string; findingCount: number; coverageKnown: boolean; error?: string }>
  preflight: { verdict: string; estimatedMinutes?: number; limits?: string[] }
}

async function run(command: string, args: string[], env: NodeJS.ProcessEnv, timeout = 20 * 60 * 1000) {
  try {
    const result = await execFileAsync(command, args, { env, timeout, windowsHide: true, maxBuffer: 12 * 1024 * 1024 })
    return String(result.stdout || '')
  } catch (error) {
    const childError = error as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number | string }
    if (typeof childError.code === 'number' && childError.code >= 1 && childError.code <= 3 && typeof childError.stdout === 'string' && childError.stdout.trim()) return childError.stdout
    const detail = typeof childError.stderr === 'string' ? childError.stderr.trim().slice(0, 500) : ''
    throw new Error(detail || childError.message || 'Sentinel Audit process failed')
  }
}

function parseJson<T>(stdout: string, label: string): T {
  try { return JSON.parse(stdout) as T } catch { throw new Error(`Sentinel Audit returned invalid ${label} JSON`) }
}

/** Run Audit on an isolated clone pinned to the PR head. The repository is never built or executed. */
export async function runSentinelAudit(input: {
  runnerPath: string
  owner: string
  repo: string
  prNumber: number
  commitSha: string
  dataDir: string
  accessToken?: string
}): Promise<SentinelAuditRun> {
  if (!SHA_RE.test(input.commitSha)) throw new Error('A full 40-character PR commit SHA is required')
  if (!Number.isInteger(input.prNumber) || input.prNumber < 1) throw new Error('A valid pull request number is required')
  if (!/^[A-Za-z0-9_.-]+$/.test(input.owner) || !/^[A-Za-z0-9_.-]+$/.test(input.repo)) throw new Error('Invalid configured GitHub repository')
  const runnerPath = path.resolve(input.runnerPath)
  if (!fs.existsSync(runnerPath) || !runnerPath.toLowerCase().endsWith('audit-runner.js')) throw new Error('SENTINEL_AUDIT_RUNNER must point to an existing audit-runner.js')
  const jobsRoot = path.resolve(input.dataDir, 'audit-jobs')
  fs.mkdirSync(jobsRoot, { recursive: true })
  const checkout = path.join(jobsRoot, `pr-${input.commitSha}-${Date.now()}`)
  const relative = path.relative(jobsRoot, checkout)
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Invalid isolated checkout path')
  const env = { ...process.env }
  if (input.accessToken) {
    env.GIT_CONFIG_COUNT = '1'
    env.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader'
    env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${input.accessToken}`).toString('base64')}`
  }
  try {
    await run('git', ['clone', '--filter=blob:none', '--no-checkout', `https://github.com/${input.owner}/${input.repo}.git`, checkout], env)
    await run('git', ['-C', checkout, 'fetch', '--no-tags', '--depth=1', 'origin', `refs/pull/${input.prNumber}/head`], env)
    await run('git', ['-C', checkout, 'checkout', '--detach', input.commitSha], env)
    const head = (await run('git', ['-C', checkout, 'rev-parse', 'HEAD'], env)).trim()
    if (head.toLowerCase() !== input.commitSha.toLowerCase()) throw new Error('The isolated checkout does not match the PR head SHA')

    const preflightRaw = await run(process.execPath, [runnerPath, 'preflight', checkout, '--commit', input.commitSha, '--json'], env)
    const preflight = parseJson<Array<{ verdict: string; estimatedMinutes?: number; limits?: string[]; reasons?: string[] }>>(preflightRaw, 'preflight')
    if (!preflight[0] || preflight[0].verdict === 'SKIP') throw new Error(`Sentinel Audit preflight stopped: ${preflight[0]?.reasons?.join('; ') || 'target not eligible'}`)

    const runRaw = await run(process.execPath, [runnerPath, 'run', checkout, '--commit', input.commitSha, '--routing', 'repo', '--json', '--keep-worktree'], env)
    const summary = parseJson<{ executionDir: string; executionId: string; pipelineStatus: string; verdict: string; analysisState: string; canClaimClean: boolean }>(runRaw, 'run')
    const executionDir = path.resolve(summary.executionDir)
    const expedientePath = path.join(executionDir, 'expediente.json')
    const expediente = JSON.parse(fs.readFileSync(expedientePath, 'utf8'))
    const targetSha = expediente?.identity?.target?.commit || expediente?.commit
    if (!targetSha || targetSha.toLowerCase() !== input.commitSha.toLowerCase()) throw new Error('Audit evidence does not identify the requested PR commit')
    return {
      commitSha: input.commitSha,
      executionId: summary.executionId,
      pipelineStatus: summary.pipelineStatus,
      verdict: summary.verdict,
      analysisState: summary.analysisState,
      canClaimClean: summary.canClaimClean,
      preflight: { verdict: preflight[0].verdict, estimatedMinutes: preflight[0].estimatedMinutes, limits: preflight[0].limits || [] },
      candidates: (expediente.candidates || []).map((candidate: any) => ({
        id: String(candidate.id || ''), severity: String(candidate.severity || candidate.priority || 'unknown'),
        file: candidate.file || candidate.location?.file, line: candidate.line || candidate.location?.line,
        summary: String(candidate.summary || candidate.title || candidate.rule || candidate.description || 'Candidate requires human adjudication'),
        evidence: (candidate.signals || []).map((signal: any) => ({
          tool: String(signal.tool || 'unknown'), rule: String(signal.rule || 'signal'), line: signal.line,
          detail: String(signal.detail || signal.description || 'No detail was provided.'),
        })),
      })),
      tools: Object.entries(expediente.tools || {}).map(([name, value]: [string, any]) => ({
        name, status: String(value.status || 'UNKNOWN'), verdict: String(value.verdict || 'UNKNOWN'),
        findingCount: Number(value.findingCount || 0), coverageKnown: !!value.coverage?.coverageKnown,
        error: value.error ? String(value.error) : undefined,
      })),
    }
  } finally {
    fs.rmSync(checkout, { recursive: true, force: true })
  }
}
