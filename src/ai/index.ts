import type { AIAnalysisResult, AIBackendStatus } from './types'
export type { AIAnalysisResult, AIBackendStatus, InstructionManipulationAttempt } from './types'
export { detectAIBackend, detectAllModels, buildSetupInstructions, checkModelHealth } from './detector'
export { analyzePR, computeScanHash } from './analyzer'
export { detectInstructionManipulation, hasInstructionManipulation } from './injection'
export { createSkills } from './skills'
export { sanitizeAIOutput, sanitizeJSONOutput, sanitizeSummary, sanitizeBulletPoint } from './sanitizer'
export { ollamaGenerate, ollamaChat, ollamaGenerateJSON, ollamaListModels } from './ollama'

export function formatPriorityLabel(p: AIAnalysisResult['priority']): string {
  return p.reviewPriority.toUpperCase()
}

export function formatPriorityScore(p: AIAnalysisResult['priority']): number {
  const pmap = { low: 1, medium: 2, high: 3, critical: 4 }
  const score = (pmap[p.reviewPriority] || 1) * 25 + (p.impactLevel === 'high' ? 10 : p.impactLevel === 'medium' ? 5 : 0)
  return Math.min(score, 100)
}
