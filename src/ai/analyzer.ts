import type { PRFile } from '../github/client'
import type { AIAnalysisResult, PRFileSummary, InstructionManipulationAttempt } from './types'
import { detectInstructionManipulation } from './injection'
import { SYSTEM_PROMPT, PER_FILE_PROMPT, AGGREGATE_PROMPT } from './prompts'
import { ollamaGenerateJSON } from './ollama'
import { sanitizeSummary, sanitizeBulletPoint } from './sanitizer'

function buildScanContext(prNumber: number, db: any): string {
  try {
    const scanResult = db.getLatestScanResult(prNumber)
    if (!scanResult) return ''
    return `Security Scan Results:
- Risk Score: ${scanResult.riskScore}
- Findings: ${scanResult.critical}C ${scanResult.high}H ${scanResult.medium}M ${scanResult.low}L
- Status: ${scanResult.riskScore > 0 ? 'issues_found' : 'clean'}`
  } catch {
    return ''
  }
}

function aggregateFilesByImportance(files: PRFile[]): PRFileSummary[] {
  return files.map(f => ({
    filename: f.filename,
    status: mapStatus(f.status),
    additions: f.additions,
    deletions: f.deletions,
    localSummary: '',
    securityRelevance: 'none' as const,
  }))
}

function mapStatus(status: string): 'added' | 'modified' | 'removed' | 'renamed' {
  if (status === 'added') return 'added'
  if (status === 'removed' || status === 'deleted') return 'removed'
  if (status === 'renamed') return 'renamed'
  return 'modified'
}

function determinePriority(files: PRFileSummary[]): { reviewPriority: 'low' | 'medium' | 'high' | 'critical'; impactLevel: 'low' | 'medium' | 'high'; estimatedComplexity: 'low' | 'medium' | 'high' } {
  const totalChanges = files.reduce((s, f) => s + f.additions + f.deletions, 0)
  const hasCriticalFiles = files.some(f => f.filename.includes('auth') || f.filename.includes('security') || f.filename.includes('secret'))
  const hasConfigChanges = files.some(f => f.filename.includes('config') || f.filename.includes('.env') || f.filename.includes('workflow') || f.filename.includes('.yml') || f.filename.includes('.yaml'))
  const hasDependencyChanges = files.some(f => f.filename === 'package.json' || f.filename === 'requirements.txt' || f.filename === 'go.mod')
  const fileCount = files.length

  let reviewPriority: 'low' | 'medium' | 'high' | 'critical' = 'low'
  let impactLevel: 'low' | 'medium' | 'high' = 'low'
  let estimatedComplexity: 'low' | 'medium' | 'high' = 'low'

  if (hasCriticalFiles) { reviewPriority = 'critical'; impactLevel = 'high' }
  else if (hasConfigChanges || hasDependencyChanges) { reviewPriority = 'high'; impactLevel = 'medium' }
  else if (fileCount > 10 || totalChanges > 500) { reviewPriority = 'medium'; impactLevel = 'medium' }

  if (fileCount > 20 || totalChanges > 1000) estimatedComplexity = 'high'
  else if (fileCount > 5 || totalChanges > 100) estimatedComplexity = 'medium'

  return { reviewPriority, impactLevel, estimatedComplexity }
}

function computeScanHash(files: { filename: string; patch?: string }[], sha: string): string {
  const crypto = require('crypto')
  const hash = crypto.createHash('sha256')
  for (const f of files) {
    hash.update(f.filename)
    hash.update(f.patch || '')
  }
  hash.update(sha)
  return hash.digest('hex').slice(0, 16)
}

async function callModelFallback<T>(modelName: string, prompt: string, systemPrompt: string, fallback: () => T): Promise<T> {
  if (!modelName || modelName === 'auto' || modelName === 'sentinel-ai-engine') {
    return fallback()
  }

  const backend = modelName.startsWith('ollama:') ? 'ollama' : modelName.startsWith('gguf:') ? 'node-llama-cpp' : 'unknown'

  switch (backend) {
    case 'ollama': {
      const ollamaModel = modelName.replace(/^ollama:/, '')
      const result = await ollamaGenerateJSON<T>(ollamaModel, prompt, systemPrompt)
      if (result !== null) return result
      console.warn(`[analyzer] Ollama returned null for ${ollamaModel}, falling back to deterministic`)
      return fallback()
    }
    case 'node-llama-cpp': {
      console.warn(`[analyzer] GGUF backend not yet implemented, falling back to deterministic`)
      return fallback()
    }
    default:
      return fallback()
  }
}

interface PerFileAnalysisResult {
  localSummary: string
  securityRelevance: 'none' | 'low' | 'medium' | 'high'
  securityNotes: string | null
  architecturalImpact: 'none' | 'local' | 'module' | 'cross-cutting'
  extractedFacts: { type: string; detail: string }[]
}

interface AggregateResult {
  executiveSummary: string[]
  architecturalChanges: { title: string; description: string; evidence: string[]; impact: string }[]
  securityRelevantChanges: { title: string; description: string; evidence: string[] }[]
  dependencies: { name: string; action: string; from?: string; to?: string }[]
  filesOfInterest: { filename: string; status: string; additions: number; deletions: number; localSummary: string; securityRelevance: string }[]
  reviewHotspots: { file: string; reason: string }[]
  reviewerNotes: string[]
  priority: { reviewPriority: string; impactLevel: string; estimatedComplexity: string }
}

function aggregateFallback(fileSummaries: PRFileSummary[], files: PRFile[], injectionAttempts: InstructionManipulationAttempt[], scanContext: string, prNumber: number, scanHash: string, scanResult: any, priority: any, hasInjection: boolean, modelName: string): AIAnalysisResult {
  return {
    prNumber,
    scanHash,
    executiveSummary: [
      `${files.length} file(s) changed (${fileSummaries.reduce((s, f) => s + f.additions, 0)} additions, ${fileSummaries.reduce((s, f) => s + f.deletions, 0)} deletions)`,
      ...(hasInjection ? ['⚠ Instruction manipulation detected in PR diff — review flagged files'] : []),
    ],
    architecturalChanges: [],
    securityRelevantChanges: injectionAttempts
      .filter(a => a.severity === 'critical' || a.severity === 'high')
      .map(a => ({
        title: `Instruction Manipulation: ${a.type.replace(/_/g, ' ')}`,
        description: a.description,
        evidence: [a.evidence.file],
      })),
    dependencies: fileSummaries
      .filter(f => f.filename === 'package.json' || f.filename === 'go.mod' || f.filename === 'requirements.txt' || f.filename === 'Cargo.toml' || f.filename === 'Gemfile')
      .map(f => ({ name: f.filename, action: 'updated' as const, from: undefined, to: undefined })),
    filesOfInterest: fileSummaries,
    reviewHotspots: fileSummaries
      .filter(f => f.filename.includes('auth') || f.filename.includes('security') || f.filename.includes('secret') || f.filename.includes('perm'))
      .map(f => ({ file: f.filename, reason: `${f.status} — security-relevant file` })),
    reviewerNotes: [
      ...(fileSummaries.length > 10 ? [`Large PR with ${fileSummaries.length} files — review hotspots first`] : []),
      ...(injectionAttempts.length > 0 ? [`Flagged ${injectionAttempts.length} instruction manipulation attempt(s) — investigate before merging`] : []),
    ],
    instructionManipulation: injectionAttempts,
    scannerCorrelation: {
      riskScore: scanResult?.riskScore ?? 0,
      findings: (scanResult?.critical ?? 0) + (scanResult?.high ?? 0) + (scanResult?.medium ?? 0) + (scanResult?.low ?? 0),
      scanStatus: scanResult ? (scanResult.riskScore > 0 ? 'issues_found' : 'clean') : 'not_scanned',
    },
    priority,
    analyzedAt: Date.now(),
    modelName,
  }
}

export async function analyzePR(
  prNumber: number,
  prTitle: string,
  prAuthor: string,
  prBody: string,
  base: string,
  head: string,
  files: PRFile[],
  sha: string,
  db: any,
  modelName = 'sentinel-ai-engine',
): Promise<AIAnalysisResult> {
  const scanHash = computeScanHash(files, sha)
  const fileSummaries = aggregateFilesByImportance(files)
  const scanContext = buildScanContext(prNumber, db)

  const injectionAttempts: InstructionManipulationAttempt[] = []
  for (const file of files) {
    const fileAttempts = detectInstructionManipulation([file])
    injectionAttempts.push(...fileAttempts)
  }

  const hasInjection = injectionAttempts.some(a => a.severity === 'critical' || a.severity === 'high')
  const priority = determinePriority(fileSummaries)
  const scanResult = db.getLatestScanResult ? db.getLatestScanResult(prNumber) : null
  const fallback = () => aggregateFallback(fileSummaries, files, injectionAttempts, scanContext, prNumber, scanHash, scanResult, priority, hasInjection, modelName)

  if (files.length === 0) return fallback()

  const aggregate = await callModelFallback<AggregateResult>(
    modelName,
    AGGREGATE_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{prAuthor}', sanitizeSummary(prAuthor))
      .replace('{base}', sanitizeSummary(base))
      .replace('{head}', sanitizeSummary(head))
      .replace('{fileAnalyses}', fileSummaries.map(f => `- ${f.filename} (${f.status}): ${f.additions}+ ${f.deletions}-`).join('\n'))
      .replace('{scanContext}', scanContext),
    SYSTEM_PROMPT,
    fallback,
  )

  if (!aggregate) return fallback()

  const sanitizedSummary = (aggregate.executiveSummary || []).map(s => sanitizeBulletPoint(s))
  const sanitizedNotes = (aggregate.reviewerNotes || []).map(s => sanitizeBulletPoint(s))
  const sanitizedHotspots = (aggregate.reviewHotspots || []).map(h => ({
    file: h.file,
    reason: sanitizeSummary(h.reason),
  }))
  const sanitizedArch = (aggregate.architecturalChanges || []).map(a => ({
    title: sanitizeSummary(a.title),
    description: sanitizeSummary(a.description),
    evidence: a.evidence || [],
    impact: a.impact as 'low' | 'medium' | 'high',
  }))
  const sanitizedSec = (aggregate.securityRelevantChanges || []).map(s => ({
    title: sanitizeSummary(s.title),
    description: sanitizeSummary(s.description),
    evidence: s.evidence || [],
  }))

  const prio = aggregate.priority || priority
  const aggrPriority = {
    reviewPriority: (['low', 'medium', 'high', 'critical'].includes(prio.reviewPriority) ? prio.reviewPriority : priority.reviewPriority) as 'low' | 'medium' | 'high' | 'critical',
    impactLevel: (['low', 'medium', 'high'].includes(prio.impactLevel) ? prio.impactLevel : priority.impactLevel) as 'low' | 'medium' | 'high',
    estimatedComplexity: (['low', 'medium', 'high'].includes(prio.estimatedComplexity) ? prio.estimatedComplexity : priority.estimatedComplexity) as 'low' | 'medium' | 'high',
  }

  return {
    prNumber,
    scanHash,
    executiveSummary: sanitizedSummary.length > 0 ? sanitizedSummary : fallback().executiveSummary,
    architecturalChanges: sanitizedArch,
    securityRelevantChanges: [
      ...sanitizedSec,
      ...injectionAttempts.filter(a => a.severity === 'critical' || a.severity === 'high').map(a => ({
        title: `Instruction Manipulation: ${a.type.replace(/_/g, ' ')}`,
        description: a.description,
        evidence: [a.evidence.file],
      })),
    ],
    dependencies: (aggregate.dependencies || []).map(d => ({
      name: sanitizeSummary(d.name),
      action: (['added', 'updated', 'removed'].includes(d.action) ? d.action : 'updated') as 'added' | 'updated' | 'removed',
      from: d.from || undefined,
      to: d.to || undefined,
    })),
    filesOfInterest: (aggregate.filesOfInterest || fileSummaries).map(f => ({
      filename: f.filename,
      status: mapStatus(f.status),
      additions: f.additions,
      deletions: f.deletions,
      localSummary: sanitizeSummary(f.localSummary),
      securityRelevance: (['none', 'low', 'medium', 'high'].includes(f.securityRelevance) ? f.securityRelevance : 'none') as 'none' | 'low' | 'medium' | 'high',
    })),
    reviewHotspots: sanitizedHotspots,
    reviewerNotes: sanitizedNotes,
    instructionManipulation: injectionAttempts,
    scannerCorrelation: {
      riskScore: scanResult?.riskScore ?? 0,
      findings: (scanResult?.critical ?? 0) + (scanResult?.high ?? 0) + (scanResult?.medium ?? 0) + (scanResult?.low ?? 0),
      scanStatus: scanResult ? (scanResult.riskScore > 0 ? 'issues_found' : 'clean') : 'not_scanned',
    },
    priority: aggrPriority,
    analyzedAt: Date.now(),
    modelName,
  }
}

export { computeScanHash }
