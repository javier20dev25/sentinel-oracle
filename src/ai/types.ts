export interface PRFileSummary {
  filename: string
  status: 'added' | 'modified' | 'removed' | 'renamed'
  additions: number
  deletions: number
  localSummary: string
  securityRelevance: 'none' | 'low' | 'medium' | 'high'
}

export interface ArchitecturalChange {
  title: string
  description: string
  evidence: string[]
  impact: 'low' | 'medium' | 'high'
}

export interface SecurityRelevantChange {
  title: string
  description: string
  evidence: string[]
}

export interface DependencyChange {
  name: string
  action: 'added' | 'updated' | 'removed'
  from?: string
  to?: string
}

export interface ReviewHotspot {
  file: string
  reason: string
}

export interface InstructionManipulationAttempt {
  type: string
  description: string
  evidence: {
    file: string
    line: number
    snippet: string
  }
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export interface AIAnalysisResult {
  prNumber: number
  scanHash: string
  executiveSummary: string[]
  architecturalChanges: ArchitecturalChange[]
  securityRelevantChanges: SecurityRelevantChange[]
  dependencies: DependencyChange[]
  filesOfInterest: PRFileSummary[]
  reviewHotspots: ReviewHotspot[]
  reviewerNotes: string[]
  instructionManipulation: InstructionManipulationAttempt[]
  scannerCorrelation: {
    riskScore: number
    findings: number
    scanStatus: string
  }
  priority: {
    reviewPriority: 'low' | 'medium' | 'high' | 'critical'
    impactLevel: 'low' | 'medium' | 'high'
    estimatedComplexity: 'low' | 'medium' | 'high'
  }
  analyzedAt: number
  modelName: string
}

export interface AIAnalysisRow {
  prNumber: number
  scanHash: string
  analysisJson: string
  priority: string
  impactLevel: string
  complexity: string
  injectionDetected: number
  injectionAttempts: string
  modelName: string
  analyzedAt: number
}

export interface AISkill {
  name: string
  description: string
  execute(...args: unknown[]): Promise<unknown>
}

export interface DetectedModel {
  id: string
  name: string
  backend: 'ollama' | 'node-llama-cpp'
  modelPath: string
}

export interface ScanAnalysisResult {
  analysis: string
  criticalIssues: string[]
  recommendations: string[]
  explanation: string
}

export interface AIBackendStatus {
  available: boolean
  backend: 'ollama' | 'node-llama-cpp' | 'none'
  modelName: string
  modelPath: string
  error?: string
  availableModels?: DetectedModel[]
}
