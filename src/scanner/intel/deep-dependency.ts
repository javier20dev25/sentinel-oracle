/**
 * EXPERIMENTAL — Dependency diff scan.
 *
 * This module downloads tarballs for two versions of a dependency and diffs
 * the file listing. It does NOT perform semantic analysis: no detection of
 * new domains, postinstall scripts, binary additions, or transitive dependency
 * changes. Use with caution.
 *
 * Future work required:
 * - Extract domains from string literals in both versions
 * - Detect new postinstall/preinstall scripts
 * - Detect new binaries in node_modules/.bin
 * - Detect new transitive dependencies
 * - Detect new requires/imports in bundled JS
 * - Detect permission changes (network/filesystem/child_process)
 */
import { gunzipSync } from 'node:zlib'
import type { DependencyDelta, IntelRisk } from './types'

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

async function download(url: string, maxBytes = 5 * 1024 * 1024): Promise<Buffer | null> {
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 15000)
    const res = await fetch(url, { signal: controller.signal })
    clearTimeout(timeout)
    if (!res.ok) return null
    const len = parseInt(res.headers.get('content-length') || '0', 10)
    if (len > maxBytes) return null
    const buf = Buffer.from(await res.arrayBuffer())
    return buf.length > maxBytes ? null : buf
  } catch {
    return null
  }
}

export async function analyzeDependencyDelta(dep: DepInfo): Promise<DependencyDelta | undefined> {
  if (!dep.fromVersion || !dep.toVersion || dep.fromVersion === dep.toVersion) return undefined

  const registry = dep.registry || 'npm'
  const urlFn = REGISTRY_URLS[registry]
  if (!urlFn) return undefined

  const fromUrl = urlFn(dep.name, dep.fromVersion)
  const toUrl = urlFn(dep.name, dep.toVersion)
  if (!fromUrl || !toUrl) return undefined

  const [fromBuf, toBuf] = await Promise.all([download(fromUrl), download(toUrl)])
  if (!fromBuf || !toBuf) return undefined

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
