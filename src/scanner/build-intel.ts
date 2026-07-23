import type { PRFile } from './rules'
import type { IntelRisk } from './intel/types'

export interface BuildToolSignal {
  tool: string
  file: string
  detail: string
  risk: IntelRisk
}

export interface DependencyChange {
  name: string
  version?: string
  signal: string
  risk: IntelRisk
}

export interface BuildScriptSignal {
  script: string
  command: string
  risk: IntelRisk
  detail: string
  file: string
}

export interface CIChange {
  file: string
  changeType: 'added' | 'modified' | 'removed'
  signals: string[]
  risk: IntelRisk
}

export interface SupplyChainSignal {
  type: string
  detail: string
  file: string
  risk: IntelRisk
}

export interface BuildIntelligence {
  verdict: 'CLEAN' | 'REVIEW' | 'CRITICAL'
  trustScore: number
  buildTools: BuildToolSignal[]
  dependencyChanges: DependencyChange[]
  buildScripts: BuildScriptSignal[]
  ciChanges: CIChange[]
  supplyChainSignals: SupplyChainSignal[]
  processIndicators: string[]
  networkIndicators: string[]
  summary: string
  risk: IntelRisk
}

const BUILD_TOOL_PATTERNS: { re: RegExp; tool: string; risk: IntelRisk }[] = [
  { re: /Dockerfile/gi, tool: 'Docker', risk: 'medium' },
  { re: /docker-compose/gi, tool: 'Docker Compose', risk: 'medium' },
  { re: /\.dockerignore/gi, tool: 'Docker', risk: 'low' },
  { re: /Makefile/gi, tool: 'Make', risk: 'low' },
  { re: /CMakeLists\.txt/gi, tool: 'CMake', risk: 'low' },
  { re: /webpack\.config/gi, tool: 'Webpack', risk: 'low' },
  { re: /vite\.config/gi, tool: 'Vite', risk: 'low' },
  { re: /rollup\.config/gi, tool: 'Rollup', risk: 'low' },
  { re: /tsconfig\.json/gi, tool: 'TypeScript', risk: 'low' },
  { re: /\.babelrc|babel\.config/gi, tool: 'Babel', risk: 'low' },
  { re: /eslint\.config|\.eslintrc/gi, tool: 'ESLint', risk: 'low' },
  { re: /prettier\.config|\.prettierrc/gi, tool: 'Prettier', risk: 'low' },
  { re: /jest\.config|vitest\.config/gi, tool: 'Test Runner', risk: 'low' },
  { re: /\.github\/workflows/gi, tool: 'GitHub Actions', risk: 'medium' },
  { re: /\.gitlab-ci\.yml/gi, tool: 'GitLab CI', risk: 'medium' },
  { re: /Jenkinsfile/gi, tool: 'Jenkins', risk: 'medium' },
  { re: /\.circleci/gi, tool: 'CircleCI', risk: 'medium' },
  { re: /terraform|\.tf$/gi, tool: 'Terraform', risk: 'medium' },
  { re: /kubernetes|k8s|helm/gi, tool: 'Kubernetes/Helm', risk: 'medium' },
]

const DEP_FILE_PATTERNS: { re: RegExp; type: string }[] = [
  { re: /package\.json$/, type: 'npm' },
  { re: /package-lock\.json$/, type: 'npm-lock' },
  { re: /yarn\.lock$/, type: 'yarn-lock' },
  { re: /pnpm-lock\.yaml$/, type: 'pnpm-lock' },
  { re: /requirements\.txt$/, type: 'pip' },
  { re: /Pipfile$/, type: 'pipenv' },
  { re: /poetry\.lock|pyproject\.toml$/, type: 'poetry' },
  { re: /go\.mod$/, type: 'go-mod' },
  { re: /go\.sum$/, type: 'go-sum' },
  { re: /Cargo\.toml$/, type: 'cargo' },
  { re: /Cargo\.lock$/, type: 'cargo-lock' },
  { re: /Gemfile$/, type: 'bundler' },
  { re: /Gemfile\.lock$/, type: 'bundler-lock' },
  { re: /pom\.xml$/, type: 'maven' },
  { re: /build\.gradle$/, type: 'gradle' },
]

const SUPPLY_CHAIN_PATTERNS: { re: RegExp; type: string; risk: IntelRisk }[] = [
  { re: /postinstall|preinstall|install\s*:/gi, type: 'Lifecycle script', risk: 'high' },
  { re: /@latest/gi, type: 'Unpinned version', risk: 'medium' },
  { re: /\*/gi, type: 'Wildcard version', risk: 'high' },
  { re: /https?:\/\/[^\s'"]+/gi, type: 'Remote URL in config', risk: 'medium' },
  { re: /eval\s*\(|new\s+Function\s*\(/gi, type: 'Dynamic code in build', risk: 'critical' },
  { re: /child_process|exec\(|execSync|spawn\(/gi, type: 'Shell execution', risk: 'high' },
  { re: /process\.env/gi, type: 'Environment access', risk: 'medium' },
]

const NETWORK_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /fetch\s*\(/gi, detail: 'fetch() call' },
  { re: /axios\.|axios\(/gi, detail: 'axios request' },
  { re: /\.get\s*\(|\.post\s*\(/gi, detail: 'HTTP client usage' },
  { re: /https?:\/\//gi, detail: 'HTTP URL reference' },
  { re: /net\.connect|net\.createConnection/gi, detail: 'Raw TCP connection' },
  { re: /dns\.resolve/gi, detail: 'DNS resolution' },
]

const PROCESS_PATTERNS: { re: RegExp; detail: string }[] = [
  { re: /child_process/gi, detail: 'child_process module import' },
  { re: /\bexec\s*\(/gi, detail: 'exec() call' },
  { re: /\bexecSync\s*\(/gi, detail: 'execSync() call' },
  { re: /\bspawn\s*\(/gi, detail: 'spawn() call' },
  { re: /\bspawnSync\s*\(/gi, detail: 'spawnSync() call' },
  { re: /\bfork\s*\(/gi, detail: 'fork() call' },
  { re: /os\.platform|process\.platform/gi, detail: 'Platform detection' },
]

function analyzePackageJson(patch: string, filename: string): {
  scripts: BuildScriptSignal[]
  deps: DependencyChange[]
  supplyChain: SupplyChainSignal[]
} {
  const scripts: BuildScriptSignal[] = []
  const deps: DependencyChange[] = []
  const supplyChain: SupplyChainSignal[] = []

  const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'))
  const removedLines = patch.split('\n').filter(l => l.startsWith('-') && !l.startsWith('---'))

  for (const line of addedLines) {
    const content = line.replace(/^\+/, '').trim()

    const scriptMatch = content.match(/"(\w[\w-]*)"\s*:\s*"(.+?)"/)
    if (scriptMatch) {
      const [, name, cmd] = scriptMatch
      const isBuildScript = ['build', 'compile', 'prepare', 'prebuild', 'postbuild', 'test', 'lint', 'prepublish', 'prepack'].includes(name)
      let risk: IntelRisk = 'low'
      let detail = `Script "${name}": ${cmd}`

      if (/\bexec\b|\bspawn\b|child_process|\$\(|`[^`]*`/.test(cmd)) {
        risk = 'high'
        detail += ' — contains shell execution'
      } else if (/\bfetch\b|curl|wget|http/.test(cmd)) {
        risk = 'medium'
        detail += ' — contains network access'
      } else if (/rm\s+-rf|rimraf|del\s+/.test(cmd)) {
        risk = 'medium'
        detail += ' — contains destructive file operations'
      }

      scripts.push({ script: name, command: cmd, risk, detail, file: filename })
    }

    for (const { re, type, risk } of SUPPLY_CHAIN_PATTERNS) {
      re.lastIndex = 0
      if (re.test(content)) {
        supplyChain.push({ type, detail: `in ${filename}: ${content.slice(0, 120)}`, file: filename, risk })
      }
    }
  }

  const addedDeps = addedLines.filter(l => /"(dependencies|devDependencies|peerDependencies|optionalDependencies)"/.test(l))
  const depSection = addedLines.some(l => /"dependencies"\s*:/.test(l)) ? 'dependencies'
    : addedLines.some(l => /"devDependencies"\s*:/.test(l)) ? 'devDependencies'
    : null

  for (const line of addedLines) {
    const depMatch = line.match(/^\+\s*"([^"]+)"\s*:\s*"([^"]+)"/)
    if (depMatch) {
      const [, name, version] = depMatch
      let risk: IntelRisk = 'low'
      let signal = `Added: ${name}@${version}`

      if (/^\*/.test(version)) {
        risk = 'high'
        signal += ' — wildcard version (supply chain risk)'
      } else if (/^\^|~/.test(version)) {
        risk = 'medium'
        signal += ' — range specifier'
      } else if (/@latest$/.test(version)) {
        risk = 'medium'
        signal += ' — pinned to latest'
      }

      deps.push({ name, version, signal, risk })
    }
  }

  return { scripts, deps, supplyChain }
}

function analyzeWorkflow(patch: string, filename: string): CIChange {
  const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'))
  const signals: string[] = []
  let maxRisk: IntelRisk = 'low'

  for (const line of addedLines) {
    const content = line.replace(/^\+/, '').trim()

    if (/pull_request_target/.test(content)) {
      signals.push('pull_request_target trigger — runs with full CI privileges')
      maxRisk = 'critical'
    }
    if (/write-all|contents:\s*write|permissions:\s*write-all/.test(content)) {
      signals.push('Excessive write permissions')
      if (maxRisk !== 'critical') maxRisk = 'high'
    }
    if (/uses:\s+\S+@(v?\d+|[a-zA-Z]+)\b/.test(content) && !/uses:\s+\S+@[a-f0-9]{40}/.test(content)) {
      signals.push('Action pinned to mutable tag (not SHA)')
      if (maxRisk !== 'critical') maxRisk = 'medium'
    }
    if (/\$\{\{\s*secrets\./.test(content) && /env:/.test(content)) {
      signals.push('Secret exposed in environment')
      if (maxRisk !== 'critical' && maxRisk !== 'high') maxRisk = 'high'
    }
    if (/container:|docker/.test(content)) {
      signals.push('Uses container/docker in CI')
      if (maxRisk !== 'critical' && maxRisk !== 'high') maxRisk = 'medium'
    }
    if (/continue-on-error:\s*true/.test(content)) {
      signals.push('continue-on-error enabled — may hide failures')
      if (maxRisk !== 'critical' && maxRisk !== 'high') maxRisk = 'medium'
    }
    if (/if:\s+always\(\)/.test(content)) {
      signals.push('always() condition — job runs regardless of prior failures')
      if (maxRisk === 'low') maxRisk = 'low'
    }
    if (/upload-artifact|download-artifact/.test(content)) {
      signals.push('Artifact transfer detected')
    }

    for (const { re, type, risk } of SUPPLY_CHAIN_PATTERNS) {
      re.lastIndex = 0
      if (re.test(content)) {
        signals.push(`${type}: ${content.slice(0, 100)}`)
        if (riskPriority(risk) > riskPriority(maxRisk)) maxRisk = risk
      }
    }
  }

  const changeType = addedLines.length > 0 && patch.split('\n').filter(l => l.startsWith('-') && !l.startsWith('---')).length === 0 ? 'added'
    : addedLines.length === 0 ? 'removed' : 'modified'

  return { file: filename, changeType, signals, risk: maxRisk }
}

function riskPriority(r: IntelRisk): number {
  return r === 'critical' ? 4 : r === 'high' ? 3 : r === 'medium' ? 2 : 1
}

function overallVerdict(trustScore: number, hasCritical: boolean, hasHigh: boolean): 'CLEAN' | 'REVIEW' | 'CRITICAL' {
  if (hasCritical) return 'CRITICAL'
  if (hasHigh || trustScore < 70) return 'REVIEW'
  return 'CLEAN'
}

export function analyzeBuildIntelligence(files: PRFile[]): BuildIntelligence {
  const buildTools: BuildToolSignal[] = []
  const allDeps: DependencyChange[] = []
  const allScripts: BuildScriptSignal[] = []
  const allSupplyChain: SupplyChainSignal[] = []
  const ciChanges: CIChange[] = []
  const processIndicators: string[] = []
  const networkIndicators: string[] = []

  let hasCritical = false
  let hasHigh = false

  for (const file of files) {
    const patch = file.patch || ''
    const filename = file.filename

    for (const { re, tool, risk } of BUILD_TOOL_PATTERNS) {
      re.lastIndex = 0
      if (re.test(filename)) {
        const already = buildTools.find(b => b.tool === tool && b.file === filename)
        if (!already) {
          buildTools.push({ tool, file: filename, detail: `${tool} configuration ${file.status === 'added' ? 'added' : file.status === 'removed' ? 'removed' : 'modified'}`, risk })
        }
      }
    }

    if (filename.endsWith('package.json') && !filename.includes('node_modules')) {
      const result = analyzePackageJson(patch, filename)
      allScripts.push(...result.scripts)
      allDeps.push(...result.deps)
      allSupplyChain.push(...result.supplyChain)
    }

    if (filename.startsWith('.github/workflows/') && (filename.endsWith('.yml') || filename.endsWith('.yaml'))) {
      ciChanges.push(analyzeWorkflow(patch, filename))
    }

    if (/Dockerfile|docker-compose/.test(filename)) {
      const addedLines = patch.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++'))
      for (const line of addedLines) {
        const content = line.replace(/^\+/, '').trim()
        if (/^FROM\s+/.test(content) && !/sha256:/.test(content) && !/\d+\.\d+\.\d+/.test(content)) {
          allSupplyChain.push({ type: 'Unpinned Docker base image', detail: `${content} in ${filename}`, file: filename, risk: 'medium' })
        }
        if (/^RUN\s+/.test(content)) {
          if (/curl|wget|apt-get install|pip install|npm install/.test(content)) {
            allSupplyChain.push({ type: 'Network fetch in Docker build', detail: `${content.slice(0, 100)} in ${filename}`, file: filename, risk: 'medium' })
          }
        }
      }
    }

    for (const { re, detail } of NETWORK_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) {
        const key = `${detail} in ${filename}`
        if (!networkIndicators.includes(key)) networkIndicators.push(key)
      }
    }

    for (const { re, detail } of PROCESS_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch)) {
        const key = `${detail} in ${filename}`
        if (!processIndicators.includes(key)) processIndicators.push(key)
      }
    }

    for (const { re, type, risk } of SUPPLY_CHAIN_PATTERNS) {
      re.lastIndex = 0
      if (re.test(patch) && !filename.endsWith('package.json')) {
        allSupplyChain.push({ type, detail: `in ${filename}`, file: filename, risk })
      }
    }
  }

  for (const s of allSupplyChain) {
    if (s.risk === 'critical') hasCritical = true
    if (s.risk === 'high') hasHigh = true
  }
  for (const c of ciChanges) {
    if (c.risk === 'critical') hasCritical = true
    if (c.risk === 'high') hasHigh = true
  }
  for (const p of processIndicators) {
    if (/exec\(|execSync\(|child_process/.test(p)) hasHigh = true
  }

  let trustScore = 100
  trustScore -= allScripts.filter(s => s.risk === 'high').length * 15
  trustScore -= allScripts.filter(s => s.risk === 'medium').length * 8
  trustScore -= allDeps.filter(d => d.risk === 'high').length * 10
  trustScore -= allDeps.filter(d => d.risk === 'medium').length * 5
  trustScore -= allSupplyChain.filter(s => s.risk === 'critical').length * 25
  trustScore -= allSupplyChain.filter(s => s.risk === 'high').length * 15
  trustScore -= allSupplyChain.filter(s => s.risk === 'medium').length * 8
  trustScore -= ciChanges.filter(c => c.risk === 'critical').length * 20
  trustScore -= ciChanges.filter(c => c.risk === 'high').length * 12
  trustScore -= processIndicators.length * 5
  trustScore -= networkIndicators.length * 3
  trustScore -= buildTools.filter(b => b.risk === 'medium').length * 3
  trustScore = Math.max(0, Math.min(100, trustScore))

  const verdict = overallVerdict(trustScore, hasCritical, hasHigh)

  const summaryParts: string[] = []
  if (buildTools.length > 0) summaryParts.push(`${buildTools.length} build tool(s) detected`)
  if (allDeps.length > 0) summaryParts.push(`${allDeps.length} dependency change(s)`)
  if (allScripts.length > 0) summaryParts.push(`${allScripts.length} build script(s) analyzed`)
  if (ciChanges.length > 0) summaryParts.push(`${ciChanges.length} CI/CD workflow(s) modified`)
  if (allSupplyChain.length > 0) summaryParts.push(`${allSupplyChain.length} supply chain signal(s)`)
  if (processIndicators.length > 0) summaryParts.push(`${processIndicators.length} process execution indicator(s)`)
  if (networkIndicators.length > 0) summaryParts.push(`${networkIndicators.length} network indicator(s)`)

  const summary = summaryParts.length > 0 ? summaryParts.join(', ') : 'No build-relevant changes detected'

  let maxRisk: IntelRisk = 'low'
  const allRisks = [...allSupplyChain.map(s => s.risk), ...ciChanges.map(c => c.risk), ...allScripts.map(s => s.risk), ...buildTools.map(b => b.risk)]
  for (const r of allRisks) {
    if (riskPriority(r) > riskPriority(maxRisk)) maxRisk = r
  }
  if (hasCritical) maxRisk = 'critical'
  else if (hasHigh && maxRisk !== 'critical') maxRisk = 'high'

  return {
    verdict,
    trustScore,
    buildTools,
    dependencyChanges: allDeps,
    buildScripts: allScripts,
    ciChanges,
    supplyChainSignals: allSupplyChain,
    processIndicators,
    networkIndicators,
    summary,
    risk: maxRisk,
  }
}
