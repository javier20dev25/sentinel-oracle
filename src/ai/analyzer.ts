import type { PRFile } from '../github/client'
import type { AIAnalysisResult, PRFileSummary, InstructionManipulationAttempt, ScanAnalysisResult, ExplanationResult } from './types'
import { detectInstructionManipulation } from './injection'
import { SYSTEM_PROMPT, PER_FILE_PROMPT, AGGREGATE_PROMPT, SCAN_ANALYSIS_PROMPT, PR_EXPLANATION_PROMPT, SCAN_EXPLANATION_PROMPT } from './prompts'
import { ollamaGenerateJSON, ollamaGenerate } from './ollama'
import { sanitizeSummary, sanitizeBulletPoint } from './sanitizer'
import { detectAIBackend } from './detector'

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

const PROMPT_FRAGMENTS = [
  'Escribe de 3 a 6 puntos', 'Escribe de dos a cuatro párrafos',
  'escriba de 3 a 6 puntos', 'escriba de dos a cuatro párrafos',
  'Write 3-6 bullet points', 'Write 2-4 paragraphs',
  'Cada punto debe describir', 'Cada bullet debe describir',
  'no solo los nombres de archivo',
]

function isResponseContaminated(text: string): boolean {
  const lower = text.toLowerCase()
  const matchCount = PROMPT_FRAGMENTS.filter(f => lower.includes(f.toLowerCase())).length
  return matchCount >= 2
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

  const totalAdd = files.reduce((s, f) => s + f.additions, 0)
  const totalDel = files.reduce((s, f) => s + f.deletions, 0)
  const addedFiles = files.filter(f => f.status === 'added')
  const modifiedFiles = files.filter(f => f.status === 'modified')
  const removedFiles = files.filter(f => f.status === 'removed' || f.status === 'deleted')
  const configFiles = files.filter(f => /config|\.env|\.yml|\.yaml|\.json|settings|\.ini/i.test(f.filename))
  const securityFiles = files.filter(f => /auth|security|secret|perm|token|cert|key|password|login|session/i.test(f.filename))
  const testFiles = files.filter(f => /test|spec|__tests__|\.test\.|\.spec\./i.test(f.filename))
  const sourceFiles = files.filter(f => /\.(ts|js|tsx|jsx|py|java|c|cpp|go|rs|rb)$/i.test(f.filename))
  const depFiles = files.filter(f => /package\.json|requirements\.txt|go\.mod|Cargo\.toml|Gemfile|pom\.xml/i.test(f.filename))
  const isLargePr = files.length > 10 || totalAdd > 500
  const isMostlyAdditions = totalAdd > 0 && totalDel < totalAdd * 0.3
  const isMostlyDeletions = totalDel > 0 && totalAdd < totalDel * 0.3
  const changeType = addedFiles.length > 0 || isMostlyAdditions ? 'feature' : isMostlyDeletions ? 'cleanup' : 'modification'

  const fallbackSummary: string[] = []
  if (files.length <= 12) {
    files.forEach(f => {
      const action = f.status === 'added' ? 'Se agregó' : f.status === 'removed' || f.status === 'deleted' ? 'Se eliminó' : 'Se modificó'
      const note = securityFiles.includes(f) ? ' — archivo sensible de seguridad' : depFiles.includes(f) ? ' — archivo de dependencias' : configFiles.includes(f) ? ' — archivo de configuración' : testFiles.includes(f) ? ' — archivo de test' : ''
      fallbackSummary.push(`${action} ${f.filename} (+${f.additions} -${f.deletions})${note}`)
    })
  } else {
    // Group by category for large PRs
    if (sourceFiles.length > 0) fallbackSummary.push(`• Se modificaron ${sourceFiles.length} archivos de código fuente (+${sourceFiles.reduce((s, f) => s + f.additions, 0)} -${sourceFiles.reduce((s, f) => s + f.deletions, 0)})`)
    if (testFiles.length > 0) fallbackSummary.push(`• Se ${testFiles.length === 1 ? 'agregó' : 'agregaron'} ${testFiles.length} archivo${testFiles.length > 1 ? 's' : ''} de test`)
    if (configFiles.length > 0) fallbackSummary.push(`• Se modificaron ${configFiles.length} archivos de configuración`)
    if (securityFiles.length > 0) fallbackSummary.push(`• Cambios en archivos de seguridad (${securityFiles.map(f => f.filename).join(', ')}) — requieren revisión cuidadosa`)
    if (depFiles.length > 0) fallbackSummary.push(`• Se actualizaron dependencias (${depFiles.map(f => f.filename).join(', ')})`)
    if (removedFiles.length > 0) fallbackSummary.push(`• Se eliminaron ${removedFiles.length} archivo${removedFiles.length > 1 ? 's' : ''}`)
  }
  if (isLargePr) fallbackSummary.push(`• PR extenso: ${files.length} archivos, ${totalAdd} añadidas, ${totalDel} eliminadas`)
  if (securityFiles.length > 0) fallbackSummary[fallbackSummary.length - 1] += ' — requiere revisión prioritaria'

  // Classify files by domain for better narrative
  const frontendFiles = files.filter(f => /public\/|static\/|\.css$|\.html$|\.vue$|\.svelte$|components\/|ui\/|views\//i.test(f.filename))
  const backendFiles = files.filter(f => /src\/|api\/|server\/|services?\/|controllers?\/|routes?\/|middleware\//i.test(f.filename) && !testFiles.includes(f))
  const infraFiles = files.filter(f => /docker|Dockerfile|\.yml$|\.yaml$|workflow|\.tf$|k8s|helm|chart/i.test(f.filename) && !configFiles.includes(f))

  const changeDesc = changeType === 'feature' ? 'una adición de funcionalidad' : changeType === 'cleanup' ? 'una limpieza o eliminación de código' : 'una modificación de código existente'

  // Build a narrative fallback instead of listing
  let fallbackArg = `ANÁLISIS DEL PR #${prNumber}:\n\n`

  // First paragraph: what kind of change
  fallbackArg += `Este PR implementa ${changeDesc} con ${files.length} archivo(s) afectados (${totalAdd} líneas añadidas, ${totalDel} eliminadas).`

  // Frontend changes
  if (frontendFiles.length > 0) {
    const imp = frontendFiles.filter(f => f.additions + f.deletions > 20)
    fallbackArg += `\n\n• 🎨 INTERFAZ DE USUARIO (${frontendFiles.length} archivo${frontendFiles.length > 1 ? 's' : ''}):`
    frontendFiles.forEach(f => {
      const detail = f.additions + f.deletions > 10 ? ` — cambio${imp.includes(f) ? ' significativo' : ''} (+${f.additions} -${f.deletions})` : ''
      fallbackArg += `\n  ${f.status === 'added' ? '+' : f.status === 'removed' ? '-' : '~'} ${f.filename}${detail}`
    })
    fallbackArg += `\n  Esto sugiere modificaciones en la interfaz visual o experiencia de usuario.`
  }

  // Backend changes
  if (backendFiles.length > 0) {
    const imp = backendFiles.filter(f => f.additions + f.deletions > 20)
    fallbackArg += `\n\n• ⚙️ LÓGICA DEL SERVIDOR (${backendFiles.length} archivo${backendFiles.length > 1 ? 's' : ''}):`
    backendFiles.forEach(f => {
      const detail = f.additions + f.deletions > 10 ? ` — cambio${imp.includes(f) ? ' significativo' : ''} (+${f.additions} -${f.deletions})` : ''
      fallbackArg += `\n  ${f.status === 'added' ? '+' : f.status === 'removed' ? '-' : '~'} ${f.filename}${detail}`
    })
    fallbackArg += `\n  Posiblemente cambios en APIs, servicios o lógica de negocio.`
  }

  // Security changes
  if (securityFiles.length > 0) {
    fallbackArg += `\n\n• 🔒 SEGURIDAD (${securityFiles.length} archivo${securityFiles.length > 1 ? 's' : ''}):`
    securityFiles.forEach(f => {
      fallbackArg += `\n  ${f.status === 'added' ? '+' : f.status === 'removed' ? '-' : '~'} ${f.filename} (+${f.additions} -${f.deletions})`
    })
    fallbackArg += `\n  ⚠ Los archivos de seguridad requieren revisión prioritaria — pueden contener credenciales, claves o lógica de autenticación.`
  }

  // Config changes
  if (configFiles.length > 0) {
    const cfgNonSecurity = configFiles.filter(f => !securityFiles.includes(f))
    if (cfgNonSecurity.length > 0) {
      fallbackArg += `\n\n• ⚙️ CONFIGURACIÓN (${cfgNonSecurity.length} archivo${cfgNonSecurity.length > 1 ? 's' : ''}):`
      cfgNonSecurity.forEach(f => fallbackArg += `\n  ~ ${f.filename}`)
      fallbackArg += `\n  Cambios en configuración que pueden afectar el entorno de ejecución.`
    }
  }

  // Infrastructure/CI changes
  if (infraFiles.length > 0) {
    fallbackArg += `\n\n• 🏗️ INFRAESTRUCTURA (${infraFiles.length} archivo${infraFiles.length > 1 ? 's' : ''}):`
    infraFiles.forEach(f => fallbackArg += `\n  ~ ${f.filename}`)
    fallbackArg += `\n  Posibles cambios en CI/CD, Docker o depliegue.`
  }

  // Dependency changes
  if (depFiles.length > 0) {
    fallbackArg += `\n\n• 📦 DEPENDENCIAS (${depFiles.length} archivo${depFiles.length > 1 ? 's' : ''}):`
    depFiles.forEach(f => fallbackArg += `\n  ~ ${f.filename}`)
    fallbackArg += `\n  Se modificaron dependencias — verificar compatibilidad con versiones actuales.`
  }

  // Test changes
  if (testFiles.length > 0) {
    fallbackArg += `\n\n• 🧪 PRUEBAS (${testFiles.length} archivo${testFiles.length > 1 ? 's' : ''}):`
    testFiles.forEach(f => fallbackArg += `\n  ${f.status === 'added' ? '+' : f.status === 'removed' ? '-' : '~'} ${f.filename}`)
    fallbackArg += `\n  Los cambios incluyen cobertura de pruebas, lo que es una buena práctica.`
  } else if (sourceFiles.length > 0 && changeType !== 'cleanup') {
    fallbackArg += `\n\n⚠ No se detectaron archivos de prueba asociados a estos cambios. Considerar agregar tests.`
  }

  // Size note
  if (isLargePr) {
    fallbackArg += `\n\n📐 PR EXTENSO: ${files.length} archivos, ${totalAdd + totalDel} líneas totales. Revisar archivos con más cambios primero.`
  }

  // Summary of removed files
  if (removedFiles.length > 0 && removedFiles.length <= 5) {
    fallbackArg += `\n\n🗑️ ARCHIVOS ELIMINADOS: ${removedFiles.map(f => f.filename).join(', ')}`
  }

  const fallback: ExplanationResult = { summary: fallbackSummary.length > 0 ? fallbackSummary : ['No se detectaron cambios significativos.'], argumentation: fallbackArg }

  let resolvedModel = modelName
  if (!resolvedModel || resolvedModel === 'auto' || resolvedModel === 'sentinel-ai-engine') {
    const status = detectAIBackend()
    if (status.available && status.backend === 'ollama') {
      resolvedModel = 'ollama:' + status.modelName
      console.log(`[explainPR] Auto-detected Ollama model: ${status.modelName}`)
    } else {
      console.warn('[explainPR] No Ollama model available, using fallback')
      return fallback
    }
  }

  const backend = resolvedModel.startsWith('ollama:') ? 'ollama' : 'unknown'
  if (backend !== 'ollama') return fallback

  const ollamaModel = resolvedModel.replace(/^ollama:/, '')
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

    // Detect if the LLM is echoing the prompt instead of analyzing
    if (isResponseContaminated(text)) {
      console.warn('[explainPR] Response contains prompt text — model is not following instructions, using fallback')
      return fallback
    }

    const parsed = parseExplanationSections(text)

    // Validate we got meaningful content
    if (parsed.summary.length === 0 && !parsed.argumentation) {
      console.warn('[explainPR] No sections found, using fallback')
      return fallback
    }

    // Extra validation: if summary bullets read like instructions, reject
    const allSummary = parsed.summary.join(' ').toLowerCase()
    if (isResponseContaminated(allSummary)) {
      console.warn('[explainPR] Parsed summary contains prompt text, using fallback')
      return fallback
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
  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length
  const lowCount = findings.filter(f => f.severity === 'low').length

  const findingsText = findings.slice(0, 30).map((f, i) => {
    const parts = [`[${i + 1}] ${(f.severity || 'info').toUpperCase()}: ${f.title || f.message || '?'}`]
    if (f.file) parts.push(`    File: ${f.file}${f.line != null ? ':' + f.line : ''}`)
    if (f.category) parts.push(`    Category: ${f.category}`)
    if (f.description) parts.push(`    Description: ${f.description}`)
    if (f.businessImpact) parts.push(`    Impact: ${f.businessImpact}`)
    if (f.code) parts.push(`    Code: ${f.code}`)
    if (f.cwe) parts.push(`    CWE: ${f.cwe}`)
    if (f.confidence != null) parts.push(`    Confidence: ${f.confidence}%`)
    if (f.recommendation) parts.push(`    Recommendation: ${f.recommendation}`)
    return parts.join('\n')
  }).join('\n\n')

  const summaryHeader = findings.length > 0
    ? `Resumen de hallazgos: ${criticalCount} crítico(s), ${highCount} alto(s), ${mediumCount} medio(s), ${lowCount} bajo(s)`
    : 'No se encontraron hallazgos de seguridad.'

  // Group findings by category/type for better fallback analysis
  const byCategory: Record<string, any[]> = {}
  findings.forEach(f => {
    const cat = f.category || f.cwe || 'general'
    if (!byCategory[cat]) byCategory[cat] = []
    byCategory[cat].push(f)
  })
  const byFile: Record<string, any[]> = {}
  findings.forEach(f => {
    const file = f.file || 'unknown'
    if (!byFile[file]) byFile[file] = []
    byFile[file].push(f)
  })
  const criticalHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high')
  const findingsWithCode = findings.filter(f => f.code)
  const hasInjection = findings.some(f => /injection|exec|eval|shell|command/i.test(f.category || '') || /injection|exec|eval|shell|command/i.test(f.title || ''))
  const hasSecrets = findings.some(f => /secret|key|password|token|credential/i.test(f.category || '') || /secret|key|password|token|credential/i.test(f.title || ''))
  const hasXss = findings.some(f => /xss|cross.?site/i.test(f.category || '') || /xss|cross.?site/i.test(f.title || ''))
  const hasSql = findings.some(f => /sql|sqli/i.test(f.category || '') || /sql|sqli/i.test(f.title || ''))
  const hasPathTraversal = findings.some(f => /path.?traversal|directory.?traversal|\.\.\//i.test(f.category || '') || /path.?traversal|directory.?traversal/i.test(f.title || ''))
  const fileCount = Object.keys(byFile).length

  const fallbackSummary: string[] = []
  if (criticalCount > 0) {
    const critFiles = findings.filter(f => f.severity === 'critical').map(f => f.file || '?').filter(Boolean)
    fallbackSummary.push(`${criticalCount} hallazgo(s) CRÍTICO(S) — ${critFiles.length > 0 ? critFiles.join(', ') : 'revisión inmediata requerida'}`)
  }
  if (highCount > 0) {
    fallbackSummary.push(`${highCount} hallazgo(s) de ALTA severidad — ${criticalHigh.filter(f => f.severity === 'high').map(f => `${f.file || '?'}: ${f.title || f.message || ''}`).join('; ')}`)
  }
  if (hasInjection) fallbackSummary.push('• Riesgo de inyección de código/comandos detectado — el atacante podría ejecutar código arbitrario')
  if (hasSecrets) fallbackSummary.push('• Posible exposición de secretos/credenciales — riesgo de acceso no autorizado a sistemas externos')
  if (hasXss) fallbackSummary.push('• Vulnerabilidad XSS — un atacante podría inyectar scripts maliciosos en el navegador')
  if (hasSql) fallbackSummary.push('• Riesgo de inyección SQL — un atacante podría manipular la base de datos')
  if (hasPathTraversal) fallbackSummary.push('• Path traversal — un atacante podría acceder a archivos fuera del directorio permitido')
  if (fallbackSummary.length < findings.length && findings.length <= 8) {
    findings.forEach(f => {
      fallbackSummary.push(`${(f.severity || 'info').toUpperCase()}: ${f.title || f.message || f.description || 'Hallazgo'} en ${f.file || '?'}`)
    })
  } else if (fallbackSummary.length < 3 && findings.length > 0) {
    fallbackSummary.push(`• Total: ${findings.length} hallazgo(s) en ${fileCount} archivo(s) (${criticalCount}C ${highCount}H ${mediumCount}M ${lowCount}L)`)
  }

  let fallbackArg = `El escaneo de seguridad detectó ${findings.length} hallazgo(s) distribuidos en ${fileCount} archivo(s). `
  if (criticalHigh.length > 0) {
    fallbackArg += `Hay ${criticalHigh.length} hallazgo(s) de severidad crítica o alta que requieren atención inmediata antes del merge. `
  }
  if (hasInjection || hasSecrets || hasXss || hasSql || hasPathTraversal) {
    fallbackArg += 'Patrones de riesgo detectados: '
    const riskPatterns: string[] = []
    if (hasInjection) riskPatterns.push('inyección de código')
    if (hasSecrets) riskPatterns.push('exposición de secretos')
    if (hasXss) riskPatterns.push('XSS')
    if (hasSql) riskPatterns.push('inyección SQL')
    if (hasPathTraversal) riskPatterns.push('path traversal')
    fallbackArg += riskPatterns.join(', ') + '. '
  }
  if (Object.keys(byCategory).length > 0) {
    const topCats = Object.entries(byCategory).sort((a, b) => b[1].length - a[1].length).slice(0, 3)
    fallbackArg += `Por categoría: ${topCats.map(([cat, finds]) => `${cat}: ${finds.length}`).join(', ')}. `
  }
  if (fileCount <= 5) {
    fallbackArg += `Archivos afectados: ${Object.entries(byFile).map(([file, finds]) => `${file} (${finds.length} hallazgo${finds.length > 1 ? 's' : ''})`).join(', ')}. `
  }
  if (findingsWithCode.length > 0) {
    fallbackArg += `${findingsWithCode.length} hallazgo(s) incluyen código ofensivo que debe revisarse y corregirse. `
  }
  fallbackArg += `Se recomienda revisar cada hallazgo, priorizando los críticos y altos, y validar que las correcciones no introduzcan nuevas vulnerabilidades.`

  const fallback: ExplanationResult = { summary: fallbackSummary.length > 0 ? fallbackSummary : ['No se encontraron hallazgos de seguridad.'], argumentation: fallbackArg }

  if (findings.length === 0) {
    return { summary: ['No se detectaron hallazgos de seguridad en este PR.'], argumentation: 'El escaneo de seguridad no encontró patrones sospechosos ni vulnerabilidades en los archivos modificados.' }
  }

  let resolvedModel = modelName
  if (!resolvedModel || resolvedModel === 'auto' || resolvedModel === 'sentinel-ai-engine') {
    const status = detectAIBackend()
    if (status.available && status.backend === 'ollama') {
      resolvedModel = 'ollama:' + status.modelName
      console.log(`[explainScan] Auto-detected Ollama model: ${status.modelName}`)
    } else {
      console.warn('[explainScan] No Ollama model available, using fallback')
      return fallback
    }
  }

  const backend = resolvedModel.startsWith('ollama:') ? 'ollama' : 'unknown'
  if (backend !== 'ollama') return fallback

  const ollamaModel = resolvedModel.replace(/^ollama:/, '')
  try {
    const prompt = SCAN_EXPLANATION_PROMPT
      .replace('{prNumber}', String(prNumber))
      .replace('{prTitle}', sanitizeSummary(prTitle))
      .replace('{findingCount}', String(findings.length))
      .replace('{criticalCount}', String(criticalCount))
      .replace('{highCount}', String(highCount))
      .replace('{mediumCount}', String(mediumCount))
      .replace('{lowCount}', String(lowCount))
      .replace('{summaryHeader}', summaryHeader)
      .replace('{findings}', findingsText)

    console.log(`[explainScan] Calling Ollama model ${ollamaModel} for PR #${prNumber} scan (${findings.length} findings)...`)
    const text = await ollamaGenerate(ollamaModel, prompt)
    console.log(`[explainScan] Ollama returned ${text.length} chars`)

    if (!text || text.length < 50) {
      console.warn('[explainScan] Response too short, using fallback')
      return fallback
    }

    // Detect if the LLM is echoing the prompt instead of analyzing
    if (isResponseContaminated(text)) {
      console.warn('[explainScan] Response contains prompt text — model is not following instructions, using fallback')
      return fallback
    }

    const parsed = parseExplanationSections(text)

    if (parsed.summary.length === 0 && !parsed.argumentation) {
      console.warn('[explainScan] No sections found, using fallback')
      return fallback
    }

    const allSummary = parsed.summary.join(' ').toLowerCase()
    if (isResponseContaminated(allSummary)) {
      console.warn('[explainScan] Parsed summary contains prompt text, using fallback')
      return fallback
    }

    return {
      summary: parsed.summary.length > 0 ? parsed.summary : fallbackSummary,
      argumentation: parsed.argumentation || text.slice(0, 3000),
    }
  } catch (err) {
    console.warn(`[explainScan] Error: ${err instanceof Error ? err.message : err}`)
    return fallback
  }
}

export { computeScanHash }
