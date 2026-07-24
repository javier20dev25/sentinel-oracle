import type { PRFile } from './rules'
import type { IntelRisk } from './intel/types'

// ── Evidence Types ────────────────────────────────────────────
export type EvidenceSource = 'diff' | 'inference' | 'pattern'

export interface EvidenceNode {
  id: string
  type: EvidenceType
  label: string
  confidence: number
  source: EvidenceSource
  file?: string
  line?: number
  detail: string
  severity: 'info' | 'warning' | 'high' | 'critical'
}

export interface EvidenceEdge {
  from: string
  to: string
  relation: EvidenceRelation
  confidence: number
}

export type EvidenceType =
  | 'TOOL_INTRODUCED'
  | 'SCRIPT_CHANGED'
  | 'DEPENDENCY_ADDED'
  | 'DEPENDENCY_REMOVED'
  | 'WORKFLOW_MODIFIED'
  | 'WORKFLOW_ADDED'
  | 'NETWORK_CAPABILITY'
  | 'PROCESS_CAPABILITY'
  | 'FILESYSTEM_CAPABILITY'
  | 'SECRET_SURFACE'
  | 'SUPPLY_CHAIN_SIGNAL'
  | 'PERMISSION_ESCALATION'
  | 'BUILD_CONFIG_CHANGED'

export type EvidenceRelation =
  | 'introduces'
  | 'depends_on'
  | 'modifies'
  | 'enables'
  | 'exposes'
  | 'requires'
  | 'escalates'

// ── Build Surface ─────────────────────────────────────────────
export interface BuildToolEntry {
  name: string
  file: string
  version?: string
  risk: IntelRisk
  evidence: string[]
}

export interface BuildScriptEntry {
  name: string
  command: string
  file: string
  risk: IntelRisk
  containsShellExec: boolean
  containsNetwork: boolean
  containsDestructiveOps: boolean
  evidence: string[]
}

export interface BuildDependencyEntry {
  name: string
  version?: string
  file: string
  changeType: 'added' | 'removed' | 'modified'
  risk: IntelRisk
  evidence: string[]
}

export interface BuildSurface {
  tools: BuildToolEntry[]
  scripts: BuildScriptEntry[]
  dependencies: BuildDependencyEntry[]
  fileCategories: {
    source: string[]
    config: string[]
    workflow: string[]
    infrastructure: string[]
    tests: string[]
    documentation: string[]
  }
}

// ── Build Chain ───────────────────────────────────────────────
export interface BuildChainStep {
  stage: 'configure' | 'compile' | 'test' | 'package' | 'deploy' | 'install' | 'unknown'
  tool: string
  file: string
  risk: IntelRisk
  detail: string
}

export interface BuildChain {
  steps: BuildChainStep[]
  expectedFlow: string[]
  deviations: string[]
}

// ── Expected Build Graph ──────────────────────────────────────
export interface ExpectedGraphEdge {
  from: string
  to: string
  type: 'produced' | 'consumed' | 'spawned' | 'configured' | 'downloaded' | 'uploaded'
  confidence: number
  file: string
}

export interface ExpectedBuildGraph {
  nodes: string[]
  edges: ExpectedGraphEdge[]
  newNodes: string[]
  removedNodes: string[]
  modifiedNodes: string[]
}

// ── Trust Engine ──────────────────────────────────────────────
export interface TrustDimension {
  name: string
  score: number
  weight: number
  evidence: string[]
  maxScore: number
}

export interface BuildChangeTrust {
  overallTrust: number
  dimensions: TrustDimension[]
  breakdown: string[]
  buildSurfaceTrust: number
  toolchainTrust: number
  dependencyTrust: number
  supplyChainTrust: number
  ciTrust: number
}

// ── Build Story ───────────────────────────────────────────────
export interface BuildStoryEvent {
  type: 'tool_introduced' | 'script_changed' | 'dependency_changed' | 'workflow_changed' | 'capability_gained' | 'capability_lost' | 'trust_decreased' | 'trust_increased'
  label: string
  detail: string
  file: string
  severity: 'info' | 'warning' | 'high' | 'critical'
  delta?: string
}

export interface BuildStory {
  title: string
  events: BuildStoryEvent[]
  summary: string
  narrative: string
  rootCause: string
  riskChange: string
}

// ── Main Result ───────────────────────────────────────────────
export interface BuildIntelligence {
  verdict: 'CLEAN' | 'REVIEW' | 'CRITICAL'
  trustScore: number
  buildSurface: BuildSurface
  buildChain: BuildChain
  expectedGraph: ExpectedBuildGraph
  trust: BuildChangeTrust
  story: BuildStory
  evidenceGraph: { nodes: EvidenceNode[]; edges: EvidenceEdge[] }
  risk: IntelRisk
}

// ── Implementation ────────────────────────────────────────────

const BUILD_TOOL_PATTERNS: { re: RegExp; name: string; risk: IntelRisk }[] = [
  { re: /Dockerfile|docker-compose/gi, name: 'Docker', risk: 'medium' },
  { re: /\.github\/workflows/gi, name: 'GitHub Actions', risk: 'medium' },
  { re: /\.gitlab-ci\.yml/gi, name: 'GitLab CI', risk: 'medium' },
  { re: /Jenkinsfile/gi, name: 'Jenkins', risk: 'medium' },
  { re: /\.circleci/gi, name: 'CircleCI', risk: 'medium' },
  { re: /Makefile|CMakeLists\.txt/gi, name: 'Make/CMake', risk: 'low' },
  { re: /webpack|vite|rollup|esbuild|babel/gi, name: 'Bundler', risk: 'low' },
  { re: /tsconfig\.json/gi, name: 'TypeScript', risk: 'low' },
  { re: /terraform|\.tf$/gi, name: 'Terraform', risk: 'medium' },
  { re: /kubernetes|k8s|helm/gi, name: 'K8s/Helm', risk: 'medium' },
  { re: /jest\.config|vitest\.config|\.mocharc/gi, name: 'Test Runner', risk: 'low' },
  { re: /eslint\.config|\.eslintrc/gi, name: 'Linter', risk: 'low' },
  { re: /prettier\.config|\.prettierrc/gi, name: 'Formatter', risk: 'low' },
]

const SUPPLY_CHAIN_SIGNALS: { re: RegExp; type: string; risk: IntelRisk }[] = [
  { re: /postinstall|preinstall|install\s*:/gi, type: 'Lifecycle script', risk: 'high' },
  { re: /\*/gi, type: 'Wildcard version', risk: 'high' },
  { re: /eval\s*\(|new\s+Function\s*\(/gi, type: 'Dynamic code execution', risk: 'critical' },
  { re: /child_process|exec\(|execSync|spawn\(/gi, type: 'Shell execution', risk: 'high' },
  { re: /curl|wget|fetch\(|axios/gi, type: 'Network fetch', risk: 'medium' },
  { re: /process\.env/gi, type: 'Environment access', risk: 'medium' },
  { re: /rm\s+-rf|rimraf/gi, type: 'Destructive operation', risk: 'medium' },
]

const NETWORK_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /fetch\s*\(/gi, detail: 'fetch() call' },
  { re: /axios\.|axios\(/gi, detail: 'axios request' },
  { re: /\.post\s*\(|\.get\s*\(/gi, detail: 'HTTP client usage' },
  { re: /net\.connect|net\.createConnection/gi, detail: 'Raw TCP connection' },
  { re: /dns\.resolve/gi, detail: 'DNS resolution' },
]

const PROCESS_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /child_process/gi, detail: 'child_process module' },
  { re: /\bexec\s*\(/gi, detail: 'exec() call' },
  { re: /\bexecSync\s*\(/gi, detail: 'execSync() call' },
  { re: /\bspawn\s*\(/gi, detail: 'spawn() call' },
  { re: /\bspawnSync\s*\(/gi, detail: 'spawnSync() call' },
  { re: /\bfork\s*\(/gi, detail: 'fork() call' },
]

function riskPriority(r: IntelRisk): number {
  return r === 'critical' ? 4 : r === 'high' ? 3 : r === 'medium' ? 2 : 1
}

function maxRisk(...risks: IntelRisk[]): IntelRisk {
  let max: IntelRisk = 'low'
  for (const r of risks) {
    if (riskPriority(r) > riskPriority(max)) max = r
  }
  return max
}

// ── Build Surface Analysis ────────────────────────────────────

function analyzeBuildSurface(files: PRFile[]): BuildSurface {
  const tools: BuildToolEntry[] = []
  const scripts: BuildScriptEntry[] = []
  const dependencies: BuildDependencyEntry[] = []
  const fileCategories: BuildSurface['fileCategories'] = {
    source: [], config: [], workflow: [], infrastructure: [], tests: [], documentation: [],
  }

  for (const file of files) {
    const patch = file.patch || ''
    const filename = file.filename
    const isAdded = file.status === 'added'
    const isRemoved = file.status === 'removed' || file.status === 'deleted'

    // Categorize file
    if (/test|spec|__tests__/i.test(filename)) fileCategories.tests.push(filename)
    else if (/\.github\/workflows|Jenkinsfile|\.gitlab-ci|\.circleci/i.test(filename)) fileCategories.workflow.push(filename)
    else if (/Dockerfile|docker-compose|\.tf$|k8s|helm|\.yml$|\.yaml$/i.test(filename)) fileCategories.infrastructure.push(filename)
    else if (/config|\.env|settings|\.ini|\.json$/i.test(filename)) fileCategories.config.push(filename)
    else if (/readme|changelog|license|\.md$/i.test(filename)) fileCategories.documentation.push(filename)
    else if (/\.(ts|js|tsx|jsx|py|java|c|cpp|go|rs|rb|vue|svelte)$/i.test(filename)) fileCategories.source.push(filename)

    // Detect build tools
    for (const { re, name, risk } of BUILD_TOOL_PATTERNS) {
      re.lastIndex = 0
      if (re.test(filename)) {
        const existing = tools.find(t => t.name === name && t.file === filename)
        if (!existing) {
          const evidence: string[] = [`${name} configuration ${isAdded ? 'added' : isRemoved ? 'removed' : 'modified'}`]
          if (isAdded) evidence.push('New build tool introduced by this PR')
          tools.push({ name, file: filename, risk, evidence })
        }
      }
    }

    // Analyze package.json scripts
    if (filename.endsWith('package.json') && !filename.includes('node_modules')) {
      const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'))
      for (const line of addedLines) {
        const content = line.replace(/^\+/, '').trim()
        const scriptMatch = content.match(/"(\w[\w-]*)"\s*:\s*"(.+?)"/)
        if (scriptMatch) {
          const [, name, cmd] = scriptMatch
          const containsShellExec = /\bexec\b|\bspawn\b|child_process|\$\(|`[^`]*`/.test(cmd)
          const containsNetwork = /\bfetch\b|curl|wget|http/.test(cmd)
          const containsDestructiveOps = /rm\s+-rf|rimraf|del\s+/.test(cmd)
          let risk: IntelRisk = 'low'
          const evidence: string[] = [`Script "${name}": ${cmd}`]
          if (containsShellExec) { risk = 'high'; evidence.push('Contains shell execution — potential code injection vector') }
          else if (containsNetwork) { risk = 'medium'; evidence.push('Contains network access — potential data exfiltration') }
          else if (containsDestructiveOps) { risk = 'medium'; evidence.push('Contains destructive file operations') }
          scripts.push({ name, command: cmd, file: filename, risk, containsShellExec, containsNetwork, containsDestructiveOps, evidence })
        }
      }

      // Analyze dependency changes
      for (const line of addedLines) {
        const depMatch = line.match(/^\+\s*"([^"]+)"\s*:\s*"([^"]+)"/)
        if (depMatch) {
          const [, name, version] = depMatch
          let risk: IntelRisk = 'low'
          const evidence: string[] = [`Added ${name}@${version}`]
          if (/^\*/.test(version)) { risk = 'high'; evidence.push('Wildcard version — supply chain risk') }
          else if (/^\^|~/.test(version)) { risk = 'medium'; evidence.push('Range specifier — not pinned') }
          dependencies.push({ name, version, file: filename, changeType: 'added', risk, evidence })
        }
      }

      const removedLines = patch.split('\n').filter(l => l.startsWith('-') && !l.startsWith('---'))
      for (const line of removedLines) {
        const depMatch = line.match(/^-\s*"([^"]+)"\s*:\s*"([^"]+)"/)
        if (depMatch) {
          const [, name, version] = depMatch
          dependencies.push({ name, version, file: filename, changeType: 'removed', risk: 'low', evidence: [`Removed ${name}@${version}`] })
        }
      }
    }
  }

  return { tools, scripts, dependencies, fileCategories }
}

// ── Build Chain Analysis ──────────────────────────────────────

function analyzeBuildChain(surface: BuildSurface, files: PRFile[]): BuildChain {
  const steps: BuildChainStep[] = []
  const expectedFlow: string[] = []
  const deviations: string[] = []

  // Detect build stages from tools and scripts
  for (const tool of surface.tools) {
    let stage: BuildChainStep['stage'] = 'unknown'
    if (/Make|CMake|TypeScript|Bundler/i.test(tool.name)) stage = 'compile'
    else if (/Docker/i.test(tool.name)) stage = 'package'
    else if (/GitHub Actions|GitLab CI|Jenkins|CircleCI/i.test(tool.name)) stage = 'deploy'
    else if (/Terraform|K8s|Helm/i.test(tool.name)) stage = 'deploy'
    else if (/Test Runner/i.test(tool.name)) stage = 'test'
    else if (/Linter|Formatter/i.test(tool.name)) stage = 'configure'
    else stage = 'unknown'

    steps.push({ stage, tool: tool.name, file: tool.file, risk: tool.risk, detail: tool.evidence.join('; ') })
  }

  for (const script of surface.scripts) {
    let stage: BuildChainStep['stage'] = 'unknown'
    if (/build|compile|prepare/i.test(script.name)) stage = 'compile'
    else if (/test|spec/i.test(script.name)) stage = 'test'
    else if (/lint|format/i.test(script.name)) stage = 'configure'
    else if (/publish|deploy|release/i.test(script.name)) stage = 'deploy'
    else if (/install|postinstall/i.test(script.name)) stage = 'install'
    else if (/package|bundle/i.test(script.name)) stage = 'package'

    steps.push({ stage, tool: script.name, file: script.file, risk: script.risk, detail: script.evidence.join('; ') })
  }

  // Build expected flow
  const stages = [...new Set(steps.map(s => s.stage))]
  const stageOrder: string[] = ['configure', 'compile', 'test', 'package', 'install', 'deploy']
  for (const s of stageOrder) {
    if ((stages as string[]).includes(s)) expectedFlow.push(s)
  }

  // Detect deviations
  const highRiskSteps = steps.filter(s => s.risk === 'high' || s.risk === 'critical')
  for (const step of highRiskSteps) {
    deviations.push(`High-risk step "${step.tool}" at stage "${step.stage}" in ${step.file}`)
  }

  const shellExecScripts = surface.scripts.filter(s => s.containsShellExec)
  for (const s of shellExecScripts) {
    deviations.push(`Shell execution in script "${s.name}" — potential injection vector`)
  }

  const networkScripts = surface.scripts.filter(s => s.containsNetwork)
  for (const s of networkScripts) {
    deviations.push(`Network access in script "${s.name}" — potential exfiltration channel`)
  }

  return { steps, expectedFlow, deviations }
}

// ── Expected Build Graph ──────────────────────────────────────

function analyzeExpectedGraph(surface: BuildSurface, chain: BuildChain, files: PRFile[]): ExpectedBuildGraph {
  const nodes: string[] = []
  const edges: ExpectedGraphEdge[] = []
  const newNodes: string[] = []
  const removedNodes: string[] = []
  const modifiedNodes: string[] = []

  // Source files as nodes
  for (const f of surface.fileCategories.source) {
    nodes.push(f)
    if (files.find(ff => ff.filename === f)?.status === 'added') newNodes.push(f)
    else if (files.find(ff => ff.filename === f)?.status === 'removed') removedNodes.push(f)
    else modifiedNodes.push(f)
  }

  // Config files as nodes
  for (const f of surface.fileCategories.config) {
    nodes.push(f)
    if (files.find(ff => ff.filename === f)?.status === 'added') newNodes.push(f)
  }

  // Workflow files as nodes
  for (const f of surface.fileCategories.workflow) {
    nodes.push(f)
    if (files.find(ff => ff.filename === f)?.status === 'added') newNodes.push(f)
  }

  // Infrastructure files as nodes
  for (const f of surface.fileCategories.infrastructure) {
    nodes.push(f)
  }

  // Dependencies as nodes
  for (const dep of surface.dependencies) {
    const nodeId = `dep:${dep.name}`
    if (!nodes.includes(nodeId)) nodes.push(nodeId)
    if (dep.changeType === 'added') newNodes.push(nodeId)
    else if (dep.changeType === 'removed') removedNodes.push(nodeId)
  }

  // Tools as nodes
  for (const tool of surface.tools) {
    const nodeId = `tool:${tool.name}`
    if (!nodes.includes(nodeId)) nodes.push(nodeId)
    if (files.find(ff => ff.filename === tool.file)?.status === 'added') newNodes.push(nodeId)
  }

  // Scripts as nodes
  for (const script of surface.scripts) {
    const nodeId = `script:${script.name}`
    if (!nodes.includes(nodeId)) nodes.push(nodeId)
  }

  // Build edges between dependencies and scripts
  for (const dep of surface.dependencies) {
    for (const script of surface.scripts) {
      edges.push({
        from: `dep:${dep.name}`,
        to: `script:${script.name}`,
        type: 'consumed',
        confidence: 0.7,
        file: script.file,
      })
    }
  }

  // Build edges between tools and workflow
  for (const tool of surface.tools) {
    for (const wf of surface.fileCategories.workflow) {
      edges.push({
        from: `tool:${tool.name}`,
        to: wf,
        type: 'configured',
        confidence: 0.8,
        file: wf,
      })
    }
  }

  // Build edges from scripts to infrastructure
  for (const script of surface.scripts) {
    for (const inf of surface.fileCategories.infrastructure) {
      edges.push({
        from: `script:${script.name}`,
        to: inf,
        type: 'produced',
        confidence: 0.6,
        file: inf,
      })
    }
  }

  return { nodes, edges, newNodes, removedNodes, modifiedNodes }
}

// ── Trust Engine ──────────────────────────────────────────────

const TRUST_DIMENSIONS: { name: string; weight: number; maxScore: number }[] = [
  { name: 'build_surface', weight: 0.25, maxScore: 100 },
  { name: 'toolchain', weight: 0.20, maxScore: 100 },
  { name: 'dependencies', weight: 0.20, maxScore: 100 },
  { name: 'supply_chain', weight: 0.20, maxScore: 100 },
  { name: 'ci_cd', weight: 0.15, maxScore: 100 },
]

function computeTrust(surface: BuildSurface, chain: BuildChain, graph: ExpectedBuildGraph, files: PRFile[]): BuildChangeTrust {
  const dimensions: TrustDimension[] = []
  const breakdown: string[] = []

  // Build Surface trust
  {
    let score = 100
    const evidence: string[] = []
    const totalFiles = Object.values(surface.fileCategories).flat().length
    score -= surface.tools.filter(t => t.risk === 'high').length * 15
    score -= surface.tools.filter(t => t.risk === 'medium').length * 8
    score -= surface.scripts.filter(s => s.containsShellExec).length * 20
    score -= surface.scripts.filter(s => s.containsNetwork).length * 10
    score -= surface.scripts.filter(s => s.containsDestructiveOps).length * 10
    if (surface.fileCategories.infrastructure.length > 0) {
      score -= surface.fileCategories.infrastructure.length * 5
      evidence.push(`${surface.fileCategories.infrastructure.length} infrastructure file(s) modified`)
    }
    if (surface.fileCategories.workflow.length > 0) {
      score -= surface.fileCategories.workflow.length * 8
      evidence.push(`${surface.fileCategories.workflow.length} workflow file(s) modified`)
    }
    evidence.push(`${surface.tools.length} build tool(s), ${surface.scripts.length} script(s), ${surface.dependencies.length} dependency change(s)`)
    dimensions.push({ name: 'build_surface', score: Math.max(0, Math.min(100, score)), weight: 0.25, evidence, maxScore: 100 })
  }

  // Toolchain trust
  {
    let score = 100
    const evidence: string[] = []
    score -= surface.tools.filter(t => t.risk === 'critical').length * 30
    score -= surface.tools.filter(t => t.risk === 'high').length * 20
    score -= surface.tools.filter(t => t.risk === 'medium').length * 10
    if (surface.tools.length === 0) {
      evidence.push('No build tools detected — cannot assess toolchain')
    } else {
      evidence.push(`${surface.tools.length} tool(s) in toolchain`)
      for (const t of surface.tools) {
        evidence.push(`  ${t.name} [${t.risk}] in ${t.file}`)
      }
    }
    dimensions.push({ name: 'toolchain', score: Math.max(0, Math.min(100, score)), weight: 0.20, evidence, maxScore: 100 })
  }

  // Dependencies trust
  {
    let score = 100
    const evidence: string[] = []
    const added = surface.dependencies.filter(d => d.changeType === 'added')
    const removed = surface.dependencies.filter(d => d.changeType === 'removed')
    score -= added.filter(d => d.risk === 'high').length * 20
    score -= added.filter(d => d.risk === 'medium').length * 10
    score -= added.filter(d => d.risk === 'low').length * 3
    if (added.length > 0) evidence.push(`${added.length} dependency(ies) added`)
    if (removed.length > 0) evidence.push(`${removed.length} dependency(ies) removed`)
    for (const d of added) {
      evidence.push(`  + ${d.name}@${d.version} [${d.risk}]`)
    }
    for (const d of removed) {
      evidence.push(`  - ${d.name}@${d.version}`)
    }
    if (added.length === 0 && removed.length === 0) {
      evidence.push('No dependency changes')
    }
    dimensions.push({ name: 'dependencies', score: Math.max(0, Math.min(100, score)), weight: 0.20, evidence, maxScore: 100 })
  }

  // Supply chain trust
  {
    let score = 100
    const evidence: string[] = []
    const supplyChainFindings: { type: string; risk: IntelRisk; file: string }[] = []

    for (const file of files) {
      const patch = file.patch || ''
      for (const { re, type, risk } of SUPPLY_CHAIN_SIGNALS) {
        re.lastIndex = 0
        if (re.test(patch)) {
          supplyChainFindings.push({ type, risk, file: file.filename })
          score -= risk === 'critical' ? 30 : risk === 'high' ? 15 : risk === 'medium' ? 8 : 3
        }
      }
    }

    if (supplyChainFindings.length > 0) {
      evidence.push(`${supplyChainFindings.length} supply chain signal(s) detected`)
      for (const f of supplyChainFindings.slice(0, 5)) {
        evidence.push(`  ${f.type} [${f.risk}] in ${f.file}`)
      }
    } else {
      evidence.push('No supply chain signals detected')
    }
    dimensions.push({ name: 'supply_chain', score: Math.max(0, Math.min(100, score)), weight: 0.20, evidence, maxScore: 100 })
  }

  // CI/CD trust
  {
    let score = 100
    const evidence: string[] = []
    const workflowFiles = files.filter(f => f.filename.startsWith('.github/workflows/'))
    const ciFiles = files.filter(f => /Jenkinsfile|\.gitlab-ci|\.circleci/.test(f.filename))

    for (const file of [...workflowFiles, ...ciFiles]) {
      const patch = file.patch || ''
      const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'))
      for (const line of addedLines) {
        const content = line.replace(/^\+/, '').trim()
        if (/pull_request_target/.test(content)) { score -= 30; evidence.push('pull_request_target trigger — full CI privileges') }
        if (/write-all|contents:\s*write/.test(content)) { score -= 20; evidence.push('Excessive write permissions') }
        if (/uses:\s+\S+@(v?\d+|[a-zA-Z]+)\b/.test(content) && !/uses:\s+\S+@[a-f0-9]{40}/.test(content)) { score -= 10; evidence.push('Action pinned to mutable tag') }
        if (/\$\{\{\s*secrets\./.test(content) && /env:/.test(content)) { score -= 15; evidence.push('Secret exposed in environment') }
        if (/continue-on-error:\s*true/.test(content)) { score -= 5; evidence.push('continue-on-error enabled') }
      }
    }

    if (workflowFiles.length + ciFiles.length === 0) {
      evidence.push('No CI/CD workflow changes')
    } else {
      evidence.push(`${workflowFiles.length + ciFiles.length} CI/CD file(s) modified`)
    }
    dimensions.push({ name: 'ci_cd', score: Math.max(0, Math.min(100, score)), weight: 0.15, evidence, maxScore: 100 })
  }

  const overallTrust = Math.round(dimensions.reduce((sum, d) => sum + d.score * d.weight, 0))
  for (const d of dimensions) breakdown.push(...d.evidence)

  return {
    overallTrust,
    dimensions,
    breakdown,
    buildSurfaceTrust: dimensions.find(d => d.name === 'build_surface')?.score || 0,
    toolchainTrust: dimensions.find(d => d.name === 'toolchain')?.score || 0,
    dependencyTrust: dimensions.find(d => d.name === 'dependencies')?.score || 0,
    supplyChainTrust: dimensions.find(d => d.name === 'supply_chain')?.score || 0,
    ciTrust: dimensions.find(d => d.name === 'ci_cd')?.score || 0,
  }
}

// ── Evidence Graph Builder ────────────────────────────────────

function buildEvidenceGraph(surface: BuildSurface, chain: BuildChain, graph: ExpectedBuildGraph, trust: BuildChangeTrust, files: PRFile[]): { nodes: EvidenceNode[]; edges: EvidenceEdge[] } {
  const nodes: EvidenceNode[] = []
  const edges: EvidenceEdge[] = []
  let nodeIdx = 0

  const makeId = () => `ev-${nodeIdx++}`

  // Tool nodes
  for (const tool of surface.tools) {
    const id = makeId()
    nodes.push({
      id,
      type: 'TOOL_INTRODUCED',
      label: tool.name,
      confidence: 0.9,
      source: 'diff',
      file: tool.file,
      detail: tool.evidence.join('; '),
      severity: tool.risk === 'critical' ? 'critical' : tool.risk === 'high' ? 'high' : tool.risk === 'medium' ? 'warning' : 'info',
    })
  }

  // Script nodes
  for (const script of surface.scripts) {
    const id = makeId()
    nodes.push({
      id,
      type: 'SCRIPT_CHANGED',
      label: `Script: ${script.name}`,
      confidence: 0.95,
      source: 'diff',
      file: script.file,
      detail: script.evidence.join('; '),
      severity: script.risk === 'critical' ? 'critical' : script.risk === 'high' ? 'high' : script.risk === 'medium' ? 'warning' : 'info',
    })
  }

  // Dependency nodes
  for (const dep of surface.dependencies) {
    const id = makeId()
    nodes.push({
      id,
      type: dep.changeType === 'added' ? 'DEPENDENCY_ADDED' : dep.changeType === 'removed' ? 'DEPENDENCY_REMOVED' : 'BUILD_CONFIG_CHANGED',
      label: dep.name,
      confidence: 0.95,
      source: 'diff',
      file: dep.file,
      detail: dep.evidence.join('; '),
      severity: dep.risk === 'critical' ? 'critical' : dep.risk === 'high' ? 'high' : dep.risk === 'medium' ? 'warning' : 'info',
    })
  }

  // Network capability nodes
  const networkFiles = files.filter(f => {
    const patch = f.patch || ''
    for (const { re } of NETWORK_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) return true
    }
    return false
  })
  for (const f of networkFiles) {
    const id = makeId()
    nodes.push({
      id,
      type: 'NETWORK_CAPABILITY',
      label: 'Network access',
      confidence: 0.8,
      source: 'pattern',
      file: f.filename,
      detail: 'PR introduces network capabilities',
      severity: 'warning',
    })
  }

  // Process capability nodes
  const processFiles = files.filter(f => {
    const patch = f.patch || ''
    for (const { re } of PROCESS_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) return true
    }
    return false
  })
  for (const f of processFiles) {
    const id = makeId()
    nodes.push({
      id,
      type: 'PROCESS_CAPABILITY',
      label: 'Process execution',
      confidence: 0.85,
      source: 'pattern',
      file: f.filename,
      detail: 'PR introduces process execution capabilities',
      severity: 'high',
    })
  }

  // Edges between nodes
  const toolNodes = nodes.filter(n => n.type === 'TOOL_INTRODUCED')
  const scriptNodes = nodes.filter(n => n.type === 'SCRIPT_CHANGED')
  const depNodes = nodes.filter(n => n.type === 'DEPENDENCY_ADDED')

  for (const dep of depNodes) {
    for (const script of scriptNodes) {
      edges.push({ from: dep.id, to: script.id, relation: 'depends_on', confidence: 0.7 })
    }
  }

  for (const tool of toolNodes) {
    for (const script of scriptNodes) {
      edges.push({ from: tool.id, to: script.id, relation: 'enables', confidence: 0.6 })
    }
  }

  return { nodes, edges }
}

// ── Build Story Builder ───────────────────────────────────────

function buildStory(surface: BuildSurface, chain: BuildChain, trust: BuildChangeTrust, files: PRFile[]): BuildStory {
  const events: BuildStoryEvent[] = []

  // Tool introductions
  for (const tool of surface.tools) {
    const isAdded = files.find(f => f.filename === tool.file)?.status === 'added'
    events.push({
      type: 'tool_introduced',
      label: `${tool.name} ${isAdded ? 'added' : 'modified'}`,
      detail: tool.evidence.join('; '),
      file: tool.file,
      severity: tool.risk === 'critical' ? 'critical' : tool.risk === 'high' ? 'high' : tool.risk === 'medium' ? 'warning' : 'info',
    })
  }

  // Script changes
  for (const script of surface.scripts) {
    events.push({
      type: 'script_changed',
      label: `Script "${script.name}" ${script.containsShellExec ? 'contains shell execution' : script.containsNetwork ? 'contains network access' : 'modified'}`,
      detail: script.evidence.join('; '),
      file: script.file,
      severity: script.risk === 'critical' ? 'critical' : script.risk === 'high' ? 'high' : script.risk === 'medium' ? 'warning' : 'info',
    })
  }

  // Dependency changes
  for (const dep of surface.dependencies) {
    events.push({
      type: 'dependency_changed',
      label: `${dep.changeType === 'added' ? 'Added' : dep.changeType === 'removed' ? 'Removed' : 'Modified'} ${dep.name}@${dep.version || '?'}`,
      detail: dep.evidence.join('; '),
      file: dep.file,
      severity: dep.risk === 'critical' ? 'critical' : dep.risk === 'high' ? 'high' : dep.risk === 'medium' ? 'warning' : 'info',
      delta: dep.changeType === 'added' ? `+ ${dep.name}@${dep.version}` : `- ${dep.name}@${dep.version}`,
    })
  }

  // Capability changes from network/process indicators
  for (const file of files) {
    const patch = file.patch || ''
    for (const { re, detail } of NETWORK_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) {
        events.push({
          type: 'capability_gained',
          label: `Network capability: ${detail}`,
          detail: `PR introduces ${detail} in ${file.filename}`,
          file: file.filename,
          severity: 'warning',
        })
        break
      }
    }
    for (const { re, detail } of PROCESS_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) {
        events.push({
          type: 'capability_gained',
          label: `Process capability: ${detail}`,
          detail: `PR introduces ${detail} in ${file.filename}`,
          file: file.filename,
          severity: 'high',
        })
        break
      }
    }
  }

  // Trust change events
  for (const dim of trust.dimensions) {
    if (dim.score < 70) {
      events.push({
        type: 'trust_decreased',
        label: `${dim.name} trust: ${dim.score}/100`,
        detail: dim.evidence.join('; '),
        file: '(aggregate)',
        severity: dim.score < 50 ? 'critical' : 'high',
      })
    }
  }

  // Build narrative
  const totalEvents = events.length
  const criticalEvents = events.filter(e => e.severity === 'critical')
  const highEvents = events.filter(e => e.severity === 'high')
  const warningEvents = events.filter(e => e.severity === 'warning')

  const title = criticalEvents.length > 0 ? 'Critical build changes detected'
    : highEvents.length > 0 ? 'High-risk build modifications'
    : warningEvents.length > 0 ? 'Build changes require review'
    : 'Low-risk build modifications'

  const summary = [
    `${totalEvents} event(s) detected`,
    criticalEvents.length > 0 ? `${criticalEvents.length} critical` : '',
    highEvents.length > 0 ? `${highEvents.length} high` : '',
    warningEvents.length > 0 ? `${warningEvents.length} warning` : '',
  ].filter(Boolean).join(', ')

  // Narrative
  const narrativeParts: string[] = []
  if (surface.tools.length > 0) {
    narrativeParts.push(`This PR ${files.some(f => f.status === 'added') ? 'introduces' : 'modifies'} ${surface.tools.map(t => t.name).join(', ')} build tool(s).`)
  }
  if (surface.scripts.length > 0) {
    const shellExec = surface.scripts.filter(s => s.containsShellExec)
    const networkScripts = surface.scripts.filter(s => s.containsNetwork)
    if (shellExec.length > 0) narrativeParts.push(`⚠ ${shellExec.length} script(s) contain shell execution: ${shellExec.map(s => `"${s.name}"`).join(', ')}.`)
    if (networkScripts.length > 0) narrativeParts.push(`⚠ ${networkScripts.length} script(s) contain network access: ${networkScripts.map(s => `"${s.name}"`).join(', ')}.`)
  }
  if (surface.dependencies.length > 0) {
    const added = surface.dependencies.filter(d => d.changeType === 'added')
    const removed = surface.dependencies.filter(d => d.changeType === 'removed')
    if (added.length > 0) narrativeParts.push(`${added.length} new dependency(ies) added: ${added.map(d => d.name).join(', ')}.`)
    if (removed.length > 0) narrativeParts.push(`${removed.length} dependency(ies) removed: ${removed.map(d => d.name).join(', ')}.`)
  }
  if (chain.deviations.length > 0) {
    narrativeParts.push(`${chain.deviations.length} deviation(s) from expected build chain: ${chain.deviations[0]}.`)
  }

  const narrative = narrativeParts.join(' ') || 'No significant build changes detected.'

  // Root cause
  let rootCause = 'No significant changes'
  if (criticalEvents.length > 0) {
    rootCause = criticalEvents[0].detail
  } else if (highEvents.length > 0) {
    rootCause = highEvents[0].detail
  } else if (warningEvents.length > 0) {
    rootCause = warningEvents[0].detail
  }

  // Risk change
  const riskChange = trust.overallTrust >= 80 ? 'Trust maintained — low risk'
    : trust.overallTrust >= 60 ? 'Trust reduced — review recommended'
    : trust.overallTrust >= 40 ? 'Trust significantly reduced — careful review required'
    : 'Trust critically reduced — immediate attention needed'

  return { title, events, summary, narrative, rootCause, riskChange }
}

// ── Main Entry Point ──────────────────────────────────────────

export function analyzeBuildIntelligence(files: PRFile[]): BuildIntelligence {
  // Stage 1: Build Surface
  const buildSurface = analyzeBuildSurface(files)

  // Stage 2: Build Chain
  const buildChain = analyzeBuildChain(buildSurface, files)

  // Stage 3: Expected Build Graph
  const expectedGraph = analyzeExpectedGraph(buildSurface, buildChain, files)

  // Stage 4: Trust Engine
  const trust = computeTrust(buildSurface, buildChain, expectedGraph, files)

  // Stage 5: Evidence Graph
  const evidenceGraph = buildEvidenceGraph(buildSurface, buildChain, expectedGraph, trust, files)

  // Stage 6: Build Story
  const story = buildStory(buildSurface, buildChain, trust, files)

  // Verdict
  const hasCritical = trust.dimensions.some(d => d.score < 30) || trust.overallTrust < 40
  const hasHigh = trust.dimensions.some(d => d.score < 60) || trust.overallTrust < 65
  const verdict = hasCritical ? 'CRITICAL' : hasHigh ? 'REVIEW' : 'CLEAN'

  // Max risk
  let maxRisk: 'low' | 'medium' | 'high' | 'critical' = 'low'
  for (const d of trust.dimensions) {
    if (d.score < 30) maxRisk = maxRisk === 'low' ? 'high' : maxRisk
    if (d.score < 60 && riskPriority('medium' as IntelRisk) > riskPriority(maxRisk as IntelRisk)) maxRisk = 'medium'
  }
  if (hasCritical) maxRisk = 'high'
  else if (hasHigh) maxRisk = 'high'

  return {
    verdict,
    trustScore: trust.overallTrust,
    buildSurface,
    buildChain,
    expectedGraph,
    trust,
    story,
    evidenceGraph,
    risk: maxRisk,
  }
}
