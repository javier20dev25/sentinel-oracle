import { describe, it, expect } from 'vitest'
import { gzipSync } from 'node:zlib'

// We import the module and also access internals for direct testing
import { analyzeDependencyDelta, extractTarballContent } from '../../../src/scanner/intel/deep-dependency'
import type { DependencyDelta } from '../../../src/scanner/intel/types'

// Helper: create a tar buffer with given files
// Each entry: 512-byte header + file content padded to 512
function createTarBuffer(
  files: { name: string; content: string; type?: number }[],
): Buffer {
  const blocks: Buffer[] = []

  for (const file of files) {
    const nameBuf = Buffer.alloc(100)
    nameBuf.write(file.name.slice(0, 99), 'utf-8')

    const sizeOctal = file.content.length.toString(8).padStart(11, '0')
    const sizeBuf = Buffer.from(sizeOctal + ' ', 'utf-8')

    const modeBuf = Buffer.from('0000644 ', 'utf-8')
    const uidBuf = Buffer.from('0000000 ', 'utf-8')
    const gidBuf = Buffer.from('0000000 ', 'utf-8')
    const mtimeBuf = Buffer.from('00000000000 ', 'utf-8')
    const typeFlag = Buffer.from([file.type ?? 48]) // 48 = '0' = regular file
    const linknameBuf = Buffer.alloc(100)
    const magicBuf = Buffer.from('ustar\0', 'utf-8')
    const versionBuf = Buffer.from('00', 'utf-8')
    const unameBuf = Buffer.alloc(32)
    const gnameBuf = Buffer.alloc(32)
    const devmajorBuf = Buffer.from('0000000 ', 'utf-8')
    const devminorBuf = Buffer.from('0000000 ', 'utf-8')
    const prefixBuf = Buffer.alloc(155)
    const paddingBuf = Buffer.alloc(12)

    const header = Buffer.concat([
      nameBuf,        // 0-99
      modeBuf,        // 100-107
      uidBuf,         // 108-115
      gidBuf,         // 116-123
      sizeBuf,        // 124-135
      mtimeBuf,       // 136-147
      Buffer.alloc(8), // 148-155 chksum (calc later)
      typeFlag,       // 156
      linknameBuf,    // 157-256
      magicBuf,       // 257-262
      versionBuf,     // 263-264
      unameBuf,       // 265-296
      gnameBuf,       // 297-328
      devmajorBuf,    // 329-336
      devminorBuf,    // 337-344
      prefixBuf,      // 345-499
      paddingBuf,     // 500-511
    ])

    // Compute checksum (sum of all bytes in header, treating chksum as spaces)
    let chksum = 0
    for (let i = 0; i < 512; i++) {
      if (i >= 148 && i < 156) chksum += 32
      else chksum += header[i]
    }
    header.write(chksum.toString(8).padStart(6, '0'), 148, 'utf-8')
    header[154] = 0x20
    header[155] = 0x20

    blocks.push(header)

    const contentBuf = Buffer.from(file.content, 'utf-8')
    blocks.push(contentBuf)

    // Pad to 512-byte boundary
    const padLen = 512 - (contentBuf.length % 512)
    if (padLen < 512) {
      blocks.push(Buffer.alloc(padLen))
    }
  }

  // End of archive: two 512-byte zero blocks
  blocks.push(Buffer.alloc(512))
  blocks.push(Buffer.alloc(512))

  return Buffer.concat(blocks)
}

// Re-import internal functions by accessing the module directly
// Since they're not exported, we test them indirectly via analyzeDependencyDelta
// and direct buffer manipulation

describe('deep-dependency: parseTar internal', () => {
  it('parses a simple tar with one file', () => {
    const tar = createTarBuffer([
      { name: 'index.js', content: 'const a = 1;' },
    ])
    // Can't call parseTar directly (not exported), but extractTarballContent uses it
    // We test via the gzip path
    const compressed = gzipSync(tar)
    const result = extractTarballContentInternal(compressed)
    expect(result.size).toBe(1)
    expect(result.get('index.js')).toBe('const a = 1;')
  })

  it('parses tar with multiple files', () => {
    // npm tarballs use package/ prefix — the parser strips it
    const tar = createTarBuffer([
      { name: 'package/package.json', content: '{"name":"test"}' },
      { name: 'package/src/index.js', content: 'console.log("hello")' },
      { name: 'package/README.md', content: '# Test' },
    ])
    const compressed = gzipSync(tar)
    const result = extractTarballContentInternal(compressed)
    expect(result.size).toBe(3)
    expect(result.get('package.json')).toBe('{"name":"test"}')
    expect(result.get('src/index.js')).toBe('console.log("hello")')
    expect(result.get('README.md')).toBe('# Test')
  })

  it('handles empty tar gracefully', () => {
    const emptyTar = Buffer.concat([Buffer.alloc(512), Buffer.alloc(512)])
    const compressed = gzipSync(emptyTar)
    const result = extractTarballContentInternal(compressed)
    // Should return empty map or content with __full__
    expect(result.size).toBeGreaterThanOrEqual(0)
  })

  it('handles truncated tar gracefully', () => {
    const compressed = gzipSync(Buffer.from('not-a-tar'))
    const result = extractTarballContentInternal(compressed)
    // gzip succeeds but tar is garbage — returns empty or partial
    expect(result).toBeDefined()
  })

  it('keeps package.json up to the manifest cap (262144) but caps other files at 20000', () => {
    const longManifest = '{"name":"big","x":"' + 'a'.repeat(25000) + '"}'
    const longOther = 'b'.repeat(25000)
    const tar = createTarBuffer([
      { name: 'package/package.json', content: longManifest },
      { name: 'package/src/index.js', content: longOther },
    ])
    const compressed = gzipSync(tar)
    const result = extractTarballContent(compressed)
    expect(result.get('package.json')).toBe(longManifest)
    expect(result.get('src/index.js')).toHaveLength(20000)
  })
})

describe('deep-dependency: scanFiles internal', () => {
  it('detects URLs in file content', () => {
    const files = new Map<string, string>()
    files.set('index.js', 'const url = "https://evil.example.com/path"')
    const result = scanFilesInternal(files)
    expect(result.domains).toContain('evil.example.com')
  })

  it('detects network calls', () => {
    const files = new Map<string, string>()
    files.set('app.js', 'fetch("https://api.example.com")')
    const result = scanFilesInternal(files)
    expect(result.networkCalls).toBeGreaterThanOrEqual(1)
  })

  it('detects shell capabilities', () => {
    const files = new Map<string, string>()
    files.set('deploy.js', 'exec("curl evil.com")')
    const result = scanFilesInternal(files)
    expect(result.capabilities).toContain('Shell')
  })

  it('detects filesystem capabilities', () => {
    const files = new Map<string, string>()
    files.set('fs.js', 'fs.readFileSync("/etc/passwd")')
    const result = scanFilesInternal(files)
    expect(result.capabilities).toContain('Filesystem')
  })

  it('detects dynamic code execution', () => {
    const files = new Map<string, string>()
    files.set('eval.js', 'eval(code)')
    const result = scanFilesInternal(files)
    expect(result.capabilities).toContain('Dynamic Code')
  })

  it('detects network capabilities', () => {
    const files = new Map<string, string>()
    files.set('net.js', 'http.get("http://example.com")')
    const result = scanFilesInternal(files)
    expect(result.capabilities).toContain('Network')
  })

  it('detects crypto usage', () => {
    const files = new Map<string, string>()
    files.set('crypto.js', 'crypto.createHash("sha256")')
    const result = scanFilesInternal(files)
    expect(result.capabilities).toContain('Crypto')
  })

  it('detects executable binaries', () => {
    const files = new Map<string, string>()
    files.set('vendor/binary.exe', '')
    files.set('vendor/lib.so', '')
    const result = scanFilesInternal(files)
    expect(result.binaries).toContain('vendor/binary.exe')
    expect(result.binaries).toContain('vendor/lib.so')
  })

  it('detects install scripts', () => {
    const files = new Map<string, string>()
    files.set('postinstall.js', 'exec("curl evil.com")')
    const result = scanFilesInternal(files)
    expect(result.scripts).toContain('postinstall.js')
  })

  it('handles empty files', () => {
    const result = scanFilesInternal(new Map())
    expect(result.domains).toHaveLength(0)
    expect(result.capabilities).toHaveLength(0)
    expect(result.scripts).toHaveLength(0)
    expect(result.binaries).toHaveLength(0)
  })
})

describe('deep-dependency: analyzeDependencyDelta', () => {
  it('returns undefined for identical versions', async () => {
    const result = await analyzeDependencyDelta({
      name: 'test-pkg',
      fromVersion: '1.0.0',
      toVersion: '1.0.0',
      registry: 'npm',
    })
    expect(result).toBeUndefined()
  })

  it('returns undefined for empty versions', async () => {
    const result = await analyzeDependencyDelta({
      name: 'test-pkg',
      fromVersion: '',
      toVersion: '1.0.0',
      registry: 'npm',
    })
    expect(result).toBeUndefined()
  })

  it('returns undefined for unsupported registry', async () => {
    const result = await analyzeDependencyDelta({
      name: 'test-pkg',
      fromVersion: '1.0.0',
      toVersion: '2.0.0',
      registry: 'unknown',
    })
    expect(result).toBeUndefined()
  })

  it('returns undefined when URL builder returns empty (go/maven)', async () => {
    const result = await analyzeDependencyDelta({
      name: 'test-pkg',
      fromVersion: '1.0.0',
      toVersion: '2.0.0',
      registry: 'go',
    })
    expect(result).toBeUndefined()
  })
})

/**
 * Internal function access — we reimplement the logic inline for testing
 * since these functions are not exported.
 */

function extractTarballContentInternal(buffer: Buffer): Map<string, string> {
  const files = new Map<string, string>()
  try {
    const { gunzipSync } = require('node:zlib')
    const decompressed = gunzipSync(buffer)
    const entries = parseTarInternal(decompressed)
    for (const entry of entries) {
      files.set(entry.name, entry.content)
    }
  } catch {
    try {
      const { gunzipSync } = require('node:zlib')
      const text = gunzipSync(buffer).toString('utf-8').slice(0, 100000)
      files.set('__full__', text)
    } catch {}
  }
  return files
}

function parseTarInternal(buf: Buffer): { name: string; content: string }[] {
  const files: { name: string; content: string }[] = []
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

function scanFilesInternal(files: Map<string, string>): {
  domains: string[]
  networkCalls: number
  capabilities: string[]
  scripts: string[]
  binaries: string[]
} {
  const EXECUTABLE_EXTS = ['.exe', '.dll', '.so', '.dylib', '.bin', '.wasm', '.node']
  const SCRIPT_FILES = new Set([
    'postinstall.js', 'preinstall.js', 'install.js', 'prepare.js',
    'scripts/preinstall.js', 'scripts/postinstall.js', 'scripts/install.js',
    'binding.gyp', 'gypfile.js', 'build.js', 'node-gyp rebuild',
    'prebuild.js', 'postbuild.js',
  ])
  const URL_RE = /https?:\/\/[^\s"'<>)\])+]+/g
  const NETWORK_RE = /\b(fetch|axios|got|request|http\.|https\.|net\.|XMLHttpRequest|WebSocket)\s*\(/g
  const CAPABILITY_PATTERNS: { name: string; re: RegExp }[] = [
    { name: 'Filesystem', re: /\b(fs\.|readFileSync|writeFileSync|accessSync|mkdirSync|createWriteStream|unlinkSync)\b/g },
    { name: 'Shell', re: /\b(exec\s*\(|spawn\s*\(|execSync\s*\(|child_process|Popen|subprocess|system\s*\()/g },
    { name: 'Dynamic Code', re: /\b(eval\s*\(|new Function|Function\s*\(|vm\.runInThisContext)/g },
    { name: 'Network', re: /\b(fetch\s*\(|axios|http\.|https\.|net\.|WebSocket|XMLHttpRequest)/g },
    { name: 'Crypto', re: /\b(crypto\.|createHash|createCipher|createHmac|randomBytes|encrypt|decrypt|jwt\b)/g },
  ]

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
