import type { PRFile } from '../github/client'
import type { AIAnalysisResult, PRFileSummary, InstructionManipulationAttempt, ScanAnalysisResult, ExplanationResult } from './types'
import { detectInstructionManipulation } from './injection'
import { SYSTEM_PROMPT, PER_FILE_PROMPT, AGGREGATE_PROMPT, SCAN_ANALYSIS_PROMPT, PR_EXPLANATION_PROMPT, SCAN_EXPLANATION_PROMPT } from './prompts'
import { ollamaGenerateJSON, ollamaGenerate } from './ollama'
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
      console.warn(`[analyzer] Ollama JSON returned null for ${ollamaModel}, trying text generation`)
      // Try text generation as second attempt
      try {
        const text = await ollamaGenerate(ollamaModel, `Briefly analyze this PR: ${prompt.slice(0, 500)}. Focus on what changed and why.`, systemPrompt)
        if (text && text.length > 30) {
          // Try to parse text as JSON in case model output JSON after all
          try {
            const cleaned = text.trim()
            const braceIdx = cleaned.indexOf('{')
            if (braceIdx !== -1) {
              const json = cleaned.slice(cleaned.indexOf('{'), cleaned.lastIndexOf('}') + 1)
              return JSON.parse(json) as T
            }
          } catch {}
        }
      } catch (e) {
        console.warn(`[analyzer] Ollama text fallback also failed: ${e instanceof Error ? e.message : e}`)
      }
      console.warn(`[analyzer] Ollama all attempts failed for ${ollamaModel}, using deterministic fallback`)
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

  const MAX_DIFF_CHARS = 3000
  const fileDiffs = files.map(f => {
    const patch = f.patch || ''
    const truncated = patch.length > MAX_DIFF_CHARS ? patch.slice(0, MAX_DIFF_CHARS) + '\n...(truncated)' : patch
    return `FILE: ${f.filename} (${f.status}, +${f.additions} -${f.deletions})\n\`\`\`diff\n${truncated}\n\`\`\``
  }).join('\n\n')

  const aggregate = await callModelFallback<AggregateResult>(
    modelName,
    AGGREGATE_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{prAuthor}', sanitizeSummary(prAuthor))
      .replace('{base}', sanitizeSummary(base))
      .replace('{head}', sanitizeSummary(head))
      .replace('{fileAnalyses}', fileDiffs)
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

function formatFindingsForAI(findings: any[]): string {
  return findings.slice(0, 20).map((f, i) => {
    return `[${i + 1}] ${f.severity || 'info'}: ${f.file || f.path || '?'} — ${f.message || f.description || f.title || '?'}`
  }).join('\n')
}

export async function analyzeScanResults(
  prNumber: number,
  prTitle: string,
  findings: any[],
  modelName = 'sentinel-ai-engine',
): Promise<ScanAnalysisResult> {
  const fallbackResult: ScanAnalysisResult = {
    analysis: `${findings.length} security finding(s) found in this PR. Review each finding for potential vulnerabilities.`,
    criticalIssues: findings.filter(f => (f.severity || '').toLowerCase() === 'critical' || (f.severity || '').toLowerCase() === 'high').map(f => `${f.file || f.path || '?'}: ${f.message || f.description || f.title || '?'}`) || ['No critical issues identified.'],
    recommendations: ['Review all findings in the security scan report', 'Address critical and high-severity issues before merging'],
    explanation: 'Each finding was detected by Sentinel\'s static analysis engine. The scanner flags patterns commonly associated with security vulnerabilities. Review flagged code sections and validate whether each pattern represents an actual risk in your specific context.',
  }

  if (!modelName || modelName === 'auto' || modelName === 'sentinel-ai-engine') {
    return fallbackResult
  }

  const backend = modelName.startsWith('ollama:') ? 'ollama' : 'unknown'
  if (backend !== 'ollama') return fallbackResult

  const ollamaModel = modelName.replace(/^ollama:/, '')
  try {
    const prompt = SCAN_ANALYSIS_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{findingCount}', String(findings.length))
      .replace('{findings}', formatFindingsForAI(findings))

    const result = await ollamaGenerateJSON<ScanAnalysisResult>(ollamaModel, prompt, SYSTEM_PROMPT)
    if (result !== null && result.analysis) return result

    // Fallback: try text generation
    const textPrompt = `Analyze these security scan findings for PR #${prNumber}: ${formatFindingsForAI(findings)}. Give a brief analysis, list critical issues, and suggest fixes.`
    const text = await ollamaGenerate(ollamaModel, textPrompt)
    if (text && text.length > 20) {
      return {
        analysis: text.slice(0, 500),
        criticalIssues: fallbackResult.criticalIssues,
        recommendations: fallbackResult.recommendations,
        explanation: text.length > 500 ? text.slice(500, 1000) : 'Review findings above.',
      }
    }
  } catch (err) {
    console.warn(`[scanAnalyze] Error: ${err instanceof Error ? err.message : err}`)
  }

  return fallbackResult
}

function parseExplanationSections(text: string): { summary: string[], argumentation: string } {
  const summaryMatch = text.match(/##\s*RESUMEN[\s\S]*?(?=##\s*ARGUMENTACI[ÓO]N|$)/i)
  const argMatch = text.match(/##\s*ARGUMENTACI[ÓO]N[\s\S]*/i)

  let summary: string[] = []
  if (summaryMatch) {
    const block = summaryMatch[0].replace(/##\s*RESUMEN/i, '').trim()
    summary = block
      .split('\n')
      .map(l => l.replace(/^[•\-\*]\s*/, '').trim())
      .filter(l => l.length > 5)
  }

  let argumentation = ''
  if (argMatch) {
    argumentation = argMatch[0].replace(/##\s*ARGUMENTACI[ÓO]N/i, '').trim()
  }

  return { summary, argumentation }
}

export async function explainPR(
  prNumber: number,
  prTitle: string,
  prAuthor: string,
  files: PRFile[],
  modelName = 'auto',
): Promise<ExplanationResult> {
  const MAX_DIFF_CHARS = 4000
  const fileDiffs = files.map(f => {
    const patch = f.patch || ''
    const truncated = patch.length > MAX_DIFF_CHARS ? patch.slice(0, MAX_DIFF_CHARS) + '\n...(truncated)' : patch
    return `FILE: ${f.filename} (${f.status}, +${f.additions} -${f.deletions})\n\`\`\`diff\n${truncated}\n\`\`\``
  }).join('\n\n')

  const fallbackSummary = files.map(f => `${f.status === 'added' ? 'Se agregó' : f.status === 'removed' || f.status === 'deleted' ? 'Se eliminó' : 'Se modificó'} ${f.filename} (+${f.additions} -${f.deletions})`)
  const fallbackArg = `Este PR modifica ${files.length} archivo(s) con un total de ${files.reduce((s, f) => s + f.additions, 0)} líneas añadidas y ${files.reduce((s, f) => s + f.deletions, 0)} líneas eliminadas. Revisa los diffs individuales para entender los cambios específicos en cada archivo.`

  const fallback: ExplanationResult = { summary: fallbackSummary, argumentation: fallbackArg }

  if (!modelName || modelName === 'auto' || modelName === 'sentinel-ai-engine') {
    return fallback
  }

  const backend = modelName.startsWith('ollama:') ? 'ollama' : 'unknown'
  if (backend !== 'ollama') return fallback

  const ollamaModel = modelName.replace(/^ollama:/, '')
  try {
    const prompt = PR_EXPLANATION_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{prAuthor}', sanitizeSummary(prAuthor))
      .replace('{fileDiffs}', fileDiffs)

    console.log(`[explainPR] Calling Ollama model ${ollamaModel} for PR #${prNumber}...`)
    const text = await ollamaGenerate(ollamaModel, prompt)
    console.log(`[explainPR] Ollama returned ${text.length} chars`)

    if (!text || text.length < 50) {
      console.warn('[explainPR] Response too short, using fallback')
      return fallback
    }

    const parsed = parseExplanationSections(text)

    // Validate we got meaningful content
    if (parsed.summary.length === 0 && !parsed.argumentation) {
      // Model didn't use section headers — treat entire response as argumentation
      return {
        summary: fallbackSummary,
        argumentation: text.slice(0, 2000),
      }
    }

    return {
      summary: parsed.summary.length > 0 ? parsed.summary : fallbackSummary,
      argumentation: parsed.argumentation || text.slice(0, 2000),
    }
  } catch (err) {
    console.warn(`[explainPR] Error: ${err instanceof Error ? err.message : err}`)
    return fallback
  }
}

export async function explainScanFindings(
  prNumber: number,
  prTitle: string,
  findings: any[],
  modelName = 'auto',
): Promise<ExplanationResult> {
  const findingsText = findings.slice(0, 20).map((f, i) => {
    const parts = [`[${i + 1}] ${(f.severity || 'info').toUpperCase()}: ${f.title || f.message || '?'}`]
    if (f.file) parts.push(`    File: ${f.file}${f.line != null ? ':' + f.line : ''}`)
    if (f.description) parts.push(`    ${f.description}`)
    if (f.code) parts.push(`    Code: ${f.code}`)
    if (f.cwe) parts.push(`    CWE: ${f.cwe}`)
    if (f.recommendation) parts.push(`    Fix: ${f.recommendation}`)
    return parts.join('\n')
  }).join('\n\n')

  const fallbackSummary = findings.slice(0, 6).map(f => `${(f.severity || 'info').toUpperCase()}: ${f.title || f.message || f.description || 'Hallazgo de seguridad'} en ${f.file || 'archivo desconocido'}`)
  const fallbackArg = `El escaneo de seguridad detectó ${findings.length} hallazgo(s) en este PR. ${findings.filter(f => f.severity === 'critical').length} son críticos, ${findings.filter(f => f.severity === 'high').length} son de severidad alta. Revisa cada hallazgo en el reporte de escaneo para evaluar el riesgo real en tu contexto.`

  const fallback: ExplanationResult = { summary: fallbackSummary.length > 0 ? fallbackSummary : ['No se encontraron hallazgos de seguridad.'], argumentation: fallbackArg }

  if (!modelName || modelName === 'auto' || modelName === 'sentinel-ai-engine') {
    return fallback
  }

  if (findings.length === 0) {
    return { summary: ['No se detectaron hallazgos de seguridad en este PR.'], argumentation: 'El escaneo de seguridad no encontró patrones sospechosos ni vulnerabilidades en los archivos modificados.' }
  }

  const backend = modelName.startsWith('ollama:') ? 'ollama' : 'unknown'
  if (backend !== 'ollama') return fallback

  const ollamaModel = modelName.replace(/^ollama:/, '')
  try {
    const prompt = SCAN_EXPLANATION_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{findingCount}', String(findings.length))
      .replace('{findings}', findingsText)

    console.log(`[explainScan] Calling Ollama model ${ollamaModel} for PR #${prNumber} scan (${findings.length} findings)...`)
    const text = await ollamaGenerate(ollamaModel, prompt)
    console.log(`[explainScan] Ollama returned ${text.length} chars`)

    if (!text || text.length < 50) {
      console.warn('[explainScan] Response too short, using fallback')
      return fallback
    }

    const parsed = parseExplanationSections(text)

    if (parsed.summary.length === 0 && !parsed.argumentation) {
      return {
        summary: fallbackSummary,
        argumentation: text.slice(0, 2000),
      }
    }

    return {
      summary: parsed.summary.length > 0 ? parsed.summary : fallbackSummary,
      argumentation: parsed.argumentation || text.slice(0, 2000),
    }
  } catch (err) {
    console.warn(`[explainScan] Error: ${err instanceof Error ? err.message : err}`)
    return fallback
  }
}

export { computeScanHash }
