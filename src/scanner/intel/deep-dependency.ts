/**
 * Dependency tarball scan.
 *
 * Diffs two published versions of a dependency (updated deps) or scans a
 * single newly-added dependency's tarball, then folds dangerous signals into
 * typed `Finding`s (the ChainDrop vector: a malicious tarball ships a
 * lifecycle script + dropper). Network is gated by SENTINEL_TARBALL_SCAN
 * (set it to '0' to disable, e.g. in hermetic tests).
 */
import { gunzipSync } from 'node:zlib'
import type { DependencyDelta, IntelRisk } from './types'
import type { Finding, PRFile } from '../rules'
import type { TarballBudget } from './tarball-budget'

interface DepInfo {
  name: string
  fromVersion: string
  toVersion: string
  registry: string
}

const REGISTRY_URLS: Record<string, (name: string, version: string) => string> = {
  npm: (name, ver) => `https://registry.npmjs.org/${encodeURIComponent(name)}/-/${name.split('/').pop()}-${ver}.tgz`,
  pypi: (name, ver) => `https://pypi.org/packages/source/${name[0]}/${name}/${name}-${ver}.tar.gz`,
  crates: (name, ver) => `https://crates.io/api/v1/crates/${name}/${ver}/download`,
  go: () => '',
  maven: () => '',
}

const EXECUTABLE_EXTS = ['.exe', '.dll', '.so', '.dylib', '.bin', '.wasm', '.node']
const SCRIPT_FILES = new Set([
  'postinstall.js', 'preinstall.js', 'install.js', 'prepare.js',
  'scripts/preinstall.js', 'scripts/postinstall.js', 'scripts/install.js',
  'binding.gyp', 'gypfile.js', 'build.js', 'node-gyp rebuild',
  'prebuild.js', 'postbuild.js',
])

interface TarballFile {
  name: string
  content: string
}

function parseTar(buf: Buffer): TarballFile[] {
  const files: TarballFile[] = []
  let offset = 0
  const size = buf.length

  while (offset + 512 <= size) {
    const header = buf.subarray(offset, offset + 512)
    if (header[0] === 0) {
      offset += 512
      continue
    }

    const nameStr = header.toString('utf-8', 0, 100).replace(/\0.*$/, '')
    const sizeStr = header.toString('utf-8', 124, 136).replace(/\0.*$/, '').trim()
    if (!nameStr || !sizeStr) {
      offset += 512
      continue
    }

    const fileSize = parseInt(sizeStr, 8)
    const typeFlag = header[156]
    const prefix = header.toString('utf-8', 345, 500).replace(/\0.*$/, '')

    offset += 512

    if (typeFlag === 0 || typeFlag === 48 || typeFlag === 49) {
      const fullName = prefix ? `${prefix}/${nameStr}` : nameStr
      const contentSize = Math.ceil(fileSize / 512) * 512
      const contentBuf = buf.subarray(offset, Math.min(offset + fileSize, size))
      const content = contentBuf.toString('utf-8').slice(0, 20000)

      if (fullName) {
        files.push({ name: fullName.replace(/^[^/]*\//, ''), content })
      }
    }

    offset += Math.ceil(fileSize / 512) * 512
    if (offset > size) break
  }

  return files
}

function extractTarballContent(buffer: Buffer): Map<string, string> {
  const files = new Map<string, string>()
  try {
    const decompressed = gunzipSync(buffer)
    const entries = parseTar(decompressed)
    for (const entry of entries) {
      files.set(entry.name, entry.content)
    }
  } catch {
    // Fallback: scan decompressed text directly
    try {
      const text = gunzipSync(buffer).toString('utf-8').slice(0, 100000)
      files.set('__full__', text)
    } catch {}
  }
  return files
}

const URL_RE = /https?:\/\/[^\s"'<>)\])+]+/g
const NETWORK_RE = /\b(fetch|axios|got|request|http\.|https\.|net\.|XMLHttpRequest|WebSocket)\s*\(/g
const CAPABILITY_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'Filesystem', re: /\b(fs\.|readFileSync|writeFileSync|accessSync|mkdirSync|createWriteStream|unlinkSync)\b/g },
  { name: 'Shell', re: /\b(exec\s*\(|spawn\s*\(|execSync\s*\(|child_process|Popen|subprocess|system\s*\()/g },
  { name: 'Dynamic Code', re: /\b(eval\s*\(|new Function|Function\s*\(|vm\.runInThisContext)/g },
  { name: 'Network', re: /\b(fetch\s*\(|axios|http\.|https\.|net\.|WebSocket|XMLHttpRequest)/g },
  { name: 'Crypto', re: /\b(crypto\.|createHash|createCipher|createHmac|randomBytes|encrypt|decrypt|jwt\b)/g },
]

function scanFiles(files: Map<string, string>) {
  const domains = new Set<string>()
  let networkCalls = 0
  const capabilities = new Set<string>()
  const scripts: string[] = []
  const binaries: string[] = []

  for (const [filename, content] of files) {
    const lower = filename.toLowerCase()
    if (EXECUTABLE_EXTS.some(ext => lower.endsWith(ext))) {
      binaries.push(filename)
    }
    const base = filename.split('/').pop() || ''
    if (SCRIPT_FILES.has(base) || lower.endsWith('.gyp') || lower.endsWith('.node')) {
      scripts.push(filename)
    }
    if (!content) continue

    URL_RE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = URL_RE.exec(content)) !== null) {
      try { domains.add(new URL(m[0]).hostname) } catch {}
    }

    NETWORK_RE.lastIndex = 0
    while ((m = NETWORK_RE.exec(content)) !== null) networkCalls++

    for (const cap of CAPABILITY_PATTERNS) {
      cap.re.lastIndex = 0
      if (cap.re.test(content)) capabilities.add(cap.name)
    }
  }

  return { domains: [...domains], networkCalls, capabilities: [...capabilities], scripts, binaries }
}

/**
 * Result of a tarball fetch. `ok:false` distinguishes a hard budget stop (the
 * body was never consumed) from HTTP/size/network failures so callers never
 * misreport a budget skip as "version not published".
 */
export type DownloadResult =
  | { ok: true; buffer: Buffer; bytes: number; ms: number }
  | { ok: false; reason: 'http' | 'too_large' | 'budget' | 'error' }

async function download(url: string, maxBytes = 5 * 1024 * 1024, budget?: TarballBudget): Promise<DownloadResult> {
  const t0 = performance.now()
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)
    const res = await fetch(url, { signal: controller.signal })
    clearTimeout(timeout)
    if (!res.ok) return { ok: false, reason: 'http' }
    const len = parseInt(res.headers.get('content-length') || '0', 10)
    if (len > maxBytes) return { ok: false, reason: 'too_large' }
    // Hard byte gate: reserve from Content-Length BEFORE reading the body. If
    // the reservation would overshoot the remaining budget, the body is never
    // consumed — spent+reserved can never exceed maxBytes even under
    // concurrency. Header-less responses fall back to soft accounting.
    const reservation = budget ? budget.reserve(len) : null
    if (budget && !reservation) return { ok: false, reason: 'budget' }
    const buffer = Buffer.from(await res.arrayBuffer())
    if (buffer.length > maxBytes) {
      reservation?.cancel()
      return { ok: false, reason: 'too_large' }
    }
    budget?.recordDownload(buffer.length, performance.now() - t0, reservation)
    return { ok: true, buffer, bytes: buffer.length, ms: performance.now() - t0 }
  } catch {
    return { ok: false, reason: 'error' }
  }
}

export async function analyzeDependencyDelta(dep: DepInfo, budget?: TarballBudget): Promise<DependencyDelta | undefined> {
  if (!dep.fromVersion || !dep.toVersion || dep.fromVersion === dep.toVersion) return undefined

  const registry = dep.registry || 'npm'
  const urlFn = REGISTRY_URLS[registry]
  if (!urlFn) return undefined

  const fromUrl = urlFn(dep.name, dep.fromVersion)
  const toUrl = urlFn(dep.name, dep.toVersion)
  if (!fromUrl || !toUrl) return undefined

  const [fromRes, toRes] = await Promise.all([download(fromUrl, undefined, budget), download(toUrl, undefined, budget)])
  if (!fromRes.ok || !toRes.ok) return undefined

  const fromBuf = fromRes.buffer
  const toBuf = toRes.buffer

  const fromFiles = extractTarballContent(fromBuf)
  const toFiles = extractTarballContent(toBuf)

  const allNames = new Set([...fromFiles.keys(), ...toFiles.keys()])
  const filesChanged = [...allNames].filter(n => {
    const a = fromFiles.get(n) ?? ''
    const b = toFiles.get(n) ?? ''
    return a !== b
  }).length

  const scan = scanFiles(toFiles)
  const oldScan = scanFiles(fromFiles)

  const newDomains = scan.domains.filter(d => !oldScan.domains.includes(d))
  const newScripts = scan.scripts.filter(s => !oldScan.scripts.includes(s))
  const newCapabilities = scan.capabilities.filter(c => !oldScan.capabilities.includes(c))
  const newBinaries = scan.binaries.filter(b => !oldScan.binaries.includes(b))

  let risk: IntelRisk = 'low'
  if (scan.capabilities.includes('Shell')) risk = 'critical'
  else if (newBinaries.length > 0 || newDomains.length > 0) risk = 'high'
  else if (newCapabilities.length > 0 || filesChanged > 100) risk = 'medium'

  return {
    packageName: dep.name,
    fromVersion: dep.fromVersion,
    toVersion: dep.toVersion,
    filesChanged,
    newDomains,
    newNetworkCalls: scan.networkCalls,
    newDependencies: [], // transitive deps require deeper analysis
    newCapabilities,
    newScripts,
    newBinaries,
    risk,
    summary: `${filesChanged} files changed, ${newDomains.length} new domains`,
  }
}

// ---------------------------------------------------------------------------
// Single-tarball scan for ADDED dependencies (ChainDrop vector)
// ---------------------------------------------------------------------------

const versionCache = new Map<string, string | null>()
const METADATA_MAX_BYTES = 20 * 1024 * 1024

async function fetchJson(url: string, maxBytes = METADATA_MAX_BYTES): Promise<unknown | null> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 10000)
  try {
    const res = await fetch(url, { signal: controller.signal })
    if (!res.ok) return null
    const len = parseInt(res.headers.get('content-length') || '0', 10)
    if (len > maxBytes) return null
    const text = await res.text()
    if (text.length > maxBytes) return null
    try { return JSON.parse(text) } catch { return null }
  } catch {
    return null
  } finally {
    clearTimeout(timeout)
  }
}

function isExactSemver(v: string): boolean {
  return /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(v)
}

function parseNumericVersion(v: string): number[] {
  return v.replace(/[^0-9.].*$/, '').split('.').map(n => parseInt(n, 10) || 0)
}

function compareSemver(a: string, b: string): number {
  const na = parseNumericVersion(a)
  const nb = parseNumericVersion(b)
  const len = Math.max(na.length, nb.length)
  for (let i = 0; i < len; i++) {
    const d = (na[i] ?? 0) - (nb[i] ?? 0)
    if (d !== 0) return d
  }
  return 0
}

/**
 * Resolve a version/range for a package against the npm registry so we can
 * tell whether the exact target is actually published. An added dependency
 * whose requested version is NOT in the registry is a supply-chain signal
 * (the ChainDrop worm published then depublished its malicious versions).
 */
export async function resolveVersion(name: string, version: string, registry = 'npm'): Promise<string | null> {
  if (registry !== 'npm') return isExactSemver(version) ? version : null
  const cacheKey = `${name}@${version}`
  if (versionCache.has(cacheKey)) return versionCache.get(cacheKey) ?? null

  const metaUrl = `https://registry.npmjs.org/${encodeURIComponent(name)}`
  const meta = await fetchJson(metaUrl) as { versions?: Record<string, unknown> } | null
  const versions = meta?.versions ? Object.keys(meta.versions) : []

  let resolved: string | null = null
  if (isExactSemver(version)) {
    if (versions.includes(version)) resolved = version
  } else {
    const op = version.match(/^[><=~^]+/)?.[0] ?? ''
    const base = version.replace(/^[><=~^]+\s*/, '').replace(/^v/, '').trim()
    const bp = base.split('.').map(n => parseInt(n, 10) || 0)
    const candidates = versions.filter(v => {
      if (!isExactSemver(v)) return false
      const vp = parseNumericVersion(v)
      const cmp = compareSemver(v, base)
      if (op.startsWith('~')) return bp.length >= 1 && vp[0] === bp[0] && bp.length >= 2 && vp[1] === bp[1] && cmp >= 0
      if (op.startsWith('^')) return bp.length >= 1 && vp[0] === bp[0] && cmp >= 0
      if (op.startsWith('>=')) return cmp >= 0
      if (op.startsWith('>')) return cmp > 0
      if (op.startsWith('<=')) return cmp <= 0
      if (op.startsWith('<')) return cmp < 0
      return bp.length >= 1 && vp[0] === bp[0]
    })
    if (candidates.length > 0) candidates.sort(compareSemver)
    resolved = candidates.length > 0 ? candidates[candidates.length - 1] : null
  }

  versionCache.set(cacheKey, resolved)
  return resolved
}

export interface TarballScanResult {
  /** Resolved published version, or null when the requested version is not published. */
  resolvedVersion: string | null
  /** Why the tarball was not analyzed, when it was not. */
  skipped?: 'not_published' | 'budget' | 'network'
  delta?: DependencyDelta
  files: Map<string, string>
  lifecycleScripts: { script: string; command: string; dangerous: boolean }[]
}

const LIFECYCLE_NAMES = new Set([
  'preinstall', 'install', 'postinstall', 'prepare', 'prepublish',
  'prepublishOnly', 'prepack', 'postpack', 'rebuild',
])

function dangerousScript(script: string, command: string): boolean {
  if (!LIFECYCLE_NAMES.has(script)) return false
  const lower = command.toLowerCase()
  if (/curl|wget|\bbash\b|\bsh\s|powershell|\bcmd\s|iwr|invoke-webrequest/.test(lower)) return true
  if (/node\s+[\w./'-]+\.(mjs|js|cjs|ts)/.test(lower)) return true
  return false
}

/**
 * Scan a single dependency tarball (for a dependency the PR adds). Everything
 * in it is "new" relative to an empty baseline, so the delta's new* fields are
 * the full signal set. Returns undefined only when the registry is unknown.
 */
export async function analyzeDependencyTarball(dep: { name: string; version: string; registry?: string }, budget?: TarballBudget): Promise<TarballScanResult | undefined> {
  const registry = dep.registry || 'npm'
  const urlFn = REGISTRY_URLS[registry]
  if (!urlFn) return undefined

  const resolved = await resolveVersion(dep.name, dep.version, registry)
  if (!resolved) {
    return { resolvedVersion: null, skipped: 'not_published', files: new Map(), lifecycleScripts: [] }
  }

  const url = urlFn(dep.name, resolved)
  if (!url) return undefined

  const res = await download(url, undefined, budget)
  if (!res.ok) {
    const skipped = res.reason === 'budget' ? 'budget' : 'network'
    return { resolvedVersion: resolved, skipped, files: new Map(), lifecycleScripts: [] }
  }

  const buf = res.buffer
  const files = extractTarballContent(buf)
  const scan = scanFiles(files)

  let risk: IntelRisk = 'low'
  if (scan.capabilities.includes('Shell')) risk = 'critical'
  else if (scan.binaries.length > 0 || scan.domains.length > 0) risk = 'high'
  else if (scan.capabilities.length > 0 || scan.scripts.length > 0) risk = 'medium'

  const delta: DependencyDelta = {
    packageName: dep.name,
    fromVersion: '',
    toVersion: resolved,
    filesChanged: files.size,
    newDomains: scan.domains,
    newNetworkCalls: scan.networkCalls,
    newDependencies: [],
    newCapabilities: scan.capabilities,
    newScripts: scan.scripts,
    newBinaries: scan.binaries,
    risk,
    summary: `${files.size} files, ${scan.domains.length} domains, ${scan.scripts.length} install scripts`,
  }

  return { resolvedVersion: resolved, delta, files, lifecycleScripts: extractLifecycleScripts(files) }
}

function extractLifecycleScripts(files: Map<string, string>): TarballScanResult['lifecycleScripts'] {
  const hooks: TarballScanResult['lifecycleScripts'] = []
  try {
    const pkgJson = JSON.parse(files.get('package.json') || '{}')
    const scripts = pkgJson?.scripts ?? {}
    for (const [script, command] of Object.entries(scripts)) {
      if (typeof command !== 'string') continue
      if (!LIFECYCLE_NAMES.has(script)) continue
      hooks.push({ script, command, dangerous: dangerousScript(script, command) })
    }
  } catch {}
  return hooks
}

/**
 * Build synthetic PRFile entries from a scanned tarball so the existing
 * rules engine (runRules) can classify the payload's code patterns.
 */
export function tarballToPRFiles(result: TarballScanResult, pkgName: string): PRFile[] {
  const out: PRFile[] = []
  let count = 0
  for (const [name, content] of result.files) {
    if (name === '__full__') continue
    if (count >= 150) break
    count++
    const lines = content.split('\n').filter(l => l.length > 0)
    out.push({
      filename: `node_modules/${pkgName}/${name}`,
      status: 'added',
      additions: Math.max(lines.length, 1),
      deletions: 0,
      patch: `@@ -0,0 +1,${Math.max(lines.length, 1)} @@\n+${lines.join('\n+')}`,
      contents_url: '',
    })
  }
  return out
}

/**
 * Findings for structural signals a code-only scan misses: install/lifecycle
 * scripts (the ChainDrop install vector) and an unpublished requested version.
 */
export function lifecycleToFindings(lifecycleScripts: TarballScanResult['lifecycleScripts'], pkgName: string, resolvedVersion: string): Finding[] {
  const findings: Finding[] = []
  const dangerous = lifecycleScripts.filter(h => h.dangerous)
  if (dangerous.length > 0) {
    findings.push({
      severity: 'critical',
      category: 'supply_chain',
      title: 'Dangerous lifecycle script in added dependency',
      description: `${pkgName}@${resolvedVersion} publishes lifecycle script(s) that download or execute code during install: ${dangerous.map(h => `${h.script}: ${h.command}`).join('; ')}`,
      file: `node_modules/${pkgName}/package.json`,
      code: dangerous[0].command,
    })
  }
  for (const hook of lifecycleScripts.filter(h => !h.dangerous)) {
    findings.push({
      severity: 'medium',
      category: 'supply_chain',
      title: 'Install-time script in added dependency',
      description: `${pkgName}@${resolvedVersion} runs '${hook.script}' during install: ${hook.command}`,
      file: `node_modules/${pkgName}/package.json`,
      code: hook.command,
    })
  }
  return findings
}

export function unverifiableVersionFinding(pkgName: string, version: string): Finding {
  return {
    severity: 'high',
    category: 'supply_chain',
    title: 'Added dependency version not published',
    description: `${pkgName}@${version} was requested in the PR but is not present in the registry — the version may be unpublished (a known attack signature: publish a malicious version, then depublish).`,
    file: 'package.json',
  }
}

export function deltaToFindings(delta: DependencyDelta): Finding[] {
  const findings: Finding[] = []
  if (delta.newCapabilities.includes('Shell')) {
    findings.push({
      severity: 'critical',
      category: 'supply_chain',
      title: 'Shell execution capability in dependency tarball',
      description: `${delta.packageName}@${delta.toVersion} code spawns processes / shells out (${delta.newScripts.join(', ') || 'scripts'}).`,
      file: `node_modules/${delta.packageName}/`,
    })
  }
  if (delta.newBinaries.length > 0) {
    findings.push({
      severity: 'high',
      category: 'supply_chain',
      title: 'Prebuilt binaries in dependency tarball',
      description: `${delta.packageName}@${delta.toVersion} ships ${delta.newBinaries.length} binary file(s): ${delta.newBinaries.slice(0, 5).join(', ')}.`,
      file: `node_modules/${delta.packageName}/`,
    })
  }
  if (delta.newDomains.length > 0) {
    findings.push({
      severity: 'medium',
      category: 'supply_chain',
      title: 'Network endpoints in dependency tarball',
      description: `${delta.packageName}@${delta.toVersion} references ${delta.newDomains.length} domain(s): ${delta.newDomains.slice(0, 5).join(', ')}.`,
      file: `node_modules/${delta.packageName}/`,
    })
  }
  return findings
}
