const CWE_MAP: Record<string, { cwe: string; impact: string; remediation: string }> = {
  secret: {
    cwe: 'CWE-798',
    impact: 'An attacker with repository access can use exposed credentials to impersonate services, access restricted data, or escalate privileges within the CI/CD pipeline.',
    remediation: 'Remove the secret from source code. Use environment variables or a secrets manager (GitHub Secrets, HashiCorp Vault). Rotate the compromised credential immediately.',
  },
  workflow: {
    cwe: 'CWE-284',
    impact: 'Vulnerable CI/CD workflows allow attackers to execute arbitrary code in the build environment, access cloud credentials, or poison the software supply chain.',
    remediation: 'Pin actions to commit SHAs instead of mutable tags. Use read-only permissions where possible. Avoid pull_request_target unless absolutely necessary.',
  },
  dependency: {
    cwe: 'CWE-1104',
    impact: 'Unpinned or unverified dependencies can be silently replaced with malicious versions, leading to supply chain compromise.',
    remediation: 'Pin dependencies to specific versions or commit hashes. Use lockfiles and verify checksums. Enable Dependabot or Renovate.',
  },
  config: {
    cwe: 'CWE-200',
    impact: 'Sensitive configuration exposed in version control can leak infrastructure details, API endpoints, or internal architecture.',
    remediation: 'Move configuration to environment-specific files not tracked in git. Use .gitignore and secret scanning pre-commit hooks.',
  },
  code: {
    cwe: 'CWE-94',
    impact: 'Code patterns that enable arbitrary code execution can lead to remote compromise, data exfiltration, or full system takeover.',
    remediation: 'Avoid eval(), dynamic require(), and string-based setTimeout. Use static analysis and code review to catch dangerous patterns before merge.',
  },
  supply_chain: {
    cwe: 'CWE-1357',
    impact: 'Supply chain weaknesses enable attackers to inject malicious code through compromised dependencies or build processes.',
    remediation: 'Use Software Bill of Materials (SBOM). Pin dependencies. Enable signature verification. Restrict build environment permissions.',
  },
}

function impactFor(category: Finding['category'], severity: Finding['severity']): string {
  const base = CWE_MAP[category]?.impact || 'This finding indicates a potential security vulnerability that requires review.'
  if (severity === 'critical') return base
  return base
}

function recommendationFor(category: Finding['category'], severity: Finding['severity'], title: string): string {
  const base = CWE_MAP[category]?.remediation || 'Review the affected code and apply security best practices.'
  if (severity === 'low') return 'Review and address during normal development cycle.'
  return base
}

function cweFor(category: Finding['category']): string {
  return CWE_MAP[category]?.cwe || 'CWE-000'
}

let findingCounter = 0
export function resetFindingCounter(): void { findingCounter = 0 }
export function nextFindingId(severity: Finding['severity']): string {
  findingCounter++
  const sev = severity.toUpperCase().slice(0, 4)
  return `SNT-${sev}-${String(findingCounter).padStart(3, '0')}`
}

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: 'secret' | 'workflow' | 'dependency' | 'config' | 'code' | 'supply_chain'
  title: string
  description: string
  file?: string
  code?: string
  line?: number
  prUrl?: string
  confidence?: number
  businessImpact?: string
  recommendation?: string
  cwe?: string
  findingId?: string
}

function enrichFinding(f: Finding): Finding {
  return {
    ...f,
    confidence: f.confidence ?? (f.severity === 'critical' ? 95 : f.severity === 'high' ? 85 : f.severity === 'medium' ? 70 : 50),
    businessImpact: f.businessImpact ?? impactFor(f.category, f.severity),
    recommendation: f.recommendation ?? recommendationFor(f.category, f.severity, f.title),
    cwe: f.cwe ?? cweFor(f.category),
    findingId: f.findingId ?? nextFindingId(f.severity),
  }
}

export interface PRFile {
  filename: string
  status: string
  additions: number
  deletions: number
  patch?: string
  contents_url: string
}

const SECRET_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /ghp_[a-zA-Z0-9]{36}/g, label: 'GitHub classic PAT (ghp_)' },
  { regex: /github_pat_[a-zA-Z0-9]{22,}/g, label: 'GitHub fine-grained PAT' },
  { regex: /gho_[a-zA-Z0-9]{36}/g, label: 'GitHub OAuth token' },
  { regex: /ghu_[a-zA-Z0-9]{36}/g, label: 'GitHub user token' },
  { regex: /ghs_[a-zA-Z0-9]{36}/g, label: 'GitHub server-to-server token' },
  { regex: /ghr_[a-zA-Z0-9]{36}/g, label: 'GitHub refresh token' },
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key ID' },
  { regex: /sk-[a-zA-Z0-9]{32,}/g, label: 'OpenAI API key' },
  { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, label: 'Private key' },]

// Parse patch to extract line number for a given match index
function lineFromPatch(patch: string, matchIndex: number): number {
  const lines = patch.split('\n')
  let newLine = 0
  for (const line of lines) {
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunk) {
      newLine = parseInt(hunk[1], 10) - 1
      continue
    }
    if (line.startsWith('+')) newLine++
    else if (line.startsWith(' ')) newLine++
  }
  return newLine
}

function extractSnippet(patch: string, matchIndex: number): string {
  const lineStart = patch.lastIndexOf('\n', matchIndex) + 1
  const lineEnd = patch.indexOf('\n', matchIndex)
  return patch.slice(lineStart, lineEnd !== -1 ? lineEnd : patch.length).replace(/^[+\- ]/, '').trim()
}

// ---- SAST Rules ----

function checkUnsafeEval(patch: string, file: string): Finding | null {
  const evalPattern = /\beval\s*\(/g
  let m = evalPattern.exec(patch)
  if (m) {
    return {
      severity: 'critical',
      category: 'code',
      title: 'Unsafe eval() detected',
      description: 'eval() executes arbitrary code from a string. If an attacker controls the input, this enables Remote Code Execution (RCE)',
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    }
  }
  const funcCtorPattern = /\bnew\s+Function\s*\(/g
  m = funcCtorPattern.exec(patch)
  if (m) {
    return {
      severity: 'high',
      category: 'code',
      title: 'Dynamic Function constructor',
      description: 'new Function() creates a function from a string at runtime, enabling arbitrary code execution',
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    }
  }
  const setTimeoutEval = /setTimeout\s*\(\s*["'`]/g
  m = setTimeoutEval.exec(patch)
  if (m) {
    return {
      severity: 'high',
      category: 'code',
      title: 'setTimeout with string argument',
      description: 'Passing a string to setTimeout() is equivalent to eval() and can lead to RCE',
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    }
  }
  return null
}

function checkObfuscation(patch: string, file: string): Finding | null {
  const base64Decode = /Buffer\.from\s*\([^)]*['"][A-Za-z0-9+/=]{20,}['"]\s*,\s*['"]base64['"]\)/g
  let m = base64Decode.exec(patch)
  if (m) {
    return {
      severity: 'high',
      category: 'code',
      title: 'Base64-decoded payload',
      description: 'Base64-decoding obfuscated strings — a common technique for hiding payloads, credentials, or configuration',
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    }
  }
  const hexString = /\\x[0-9a-fA-F]{2}/g
  const hexMatches = patch.match(hexString)
  if (hexMatches && hexMatches.length > 5) {
    const firstHex = hexString.exec(patch)
    return {
      severity: 'high',
      category: 'code',
      title: 'Hex-encoded obfuscation',
      description: 'Multiple hex-encoded strings suggest obfuscated JavaScript, often used to bypass static analysis',
      file,
      code: extractSnippet(patch, firstHex ? firstHex.index : 0),
      line: lineFromPatch(patch, firstHex ? firstHex.index : 0),
    }
  }
  const arrayMap = /\[[^\]]*\]\s*\[/g
  if (/\[['"][a-zA-Z]/.test(patch) && patch.includes('\\x') && arrayMap.test(patch)) {
    return {
      severity: 'high',
      category: 'code',
      title: 'Obfuscated JavaScript (array-based string mapping)',
      description: 'Array-based string lookup combined with hex encoding is a hallmark of obfuscated/packed JavaScript payloads',
      file,
    }
  }
  return null
}

function checkEnvAccess(patch: string, file: string): Finding | null {
  const envPatterns = [/process\.env\.\w+/g, /process\.env\[\s*['"]\w+['"]\s*\]/g]
  const matches: string[] = []
  const matchPositions: number[] = []
  for (const re of envPatterns) {
    re.lastIndex = 0
    let m
    while ((m = re.exec(patch)) !== null) {
      matches.push(m[0])
      matchPositions.push(m.index)
    }
  }
  if (matches.length > 0) {
    const hasToken = matches.some(m => /TOKEN|SECRET|KEY|PASS|CRED|AUTH/i.test(m))
    const firstPos = matchPositions[0]
    return {
      severity: hasToken ? 'high' : 'medium',
      category: 'secret',
      title: 'Environment variable access detected',
      description: hasToken
        ? `Reads secrets/tokens from environment: ${matches.join(', ')}. These can be exfiltrated if the code is compromised`
        : `Reads environment variables: ${matches.join(', ')}. Verify this is necessary`,
      file,
      code: extractSnippet(patch, firstPos),
      line: lineFromPatch(patch, firstPos),
    }
  }
  return null
}

function checkNetworkExfil(patch: string, file: string): Finding[] {
  const findings: Finding[] = []
  const netPattern = /(?:await\s+)?(?:fetch|axios|got|superagent|request)\s*\(/g
  netPattern.lastIndex = 0
  let m = netPattern.exec(patch)
  if (m) {
    const urlMatch = patch.match(/['"](https?:\/\/[^'"]+)['"]/)
    const url = urlMatch ? urlMatch[1] : 'unknown URL'
    findings.push({
      severity: 'medium',
      category: 'code',
      title: 'Outbound network request',
      description: `Makes outbound HTTP request to ${url}. Could exfiltrate secrets, download payloads, or phone home to a C2 server`,
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    })
  }
  const postPattern = /\.post\s*\(/g
  m = postPattern.exec(patch)
  const getPattern = /\.get\s*\(/g
  const getM = getPattern.exec(patch)
  if (m && getM) {
    findings.push({
      severity: 'low',
      category: 'code',
      title: 'HTTP client with POST/GET',
      description: 'Code sends data via HTTP POST — potential exfiltration channel if combined with env secrets',
      file,
      code: extractSnippet(patch, Math.min(m.index, getM.index)),
      line: lineFromPatch(patch, Math.min(m.index, getM.index)),
    })
  }
  return findings
}

function checkOSCommand(patch: string, file: string): Finding | null {
  const osPatterns = [
    { re: /require\(['"]child_process['"]\)/g, snippet: true },
    { re: /\bexec\(/g, snippet: true },
    { re: /\bexecSync\(/g, snippet: true },
    { re: /\bspawn\(/g, snippet: true },
    { re: /\bspawnSync\(/g, snippet: true },
    { re: /\bfork\(/g, snippet: true },
  ]
  for (const { re } of osPatterns) {
    re.lastIndex = 0
    const m = re.exec(patch)
    if (m) {
      return {
        severity: 'high',
        category: 'code',
        title: 'OS command execution detected',
        description: 'Executes system commands via child_process. If arguments are dynamic, this enables RCE',
        file,
        code: extractSnippet(patch, m.index),
        line: lineFromPatch(patch, m.index),
      }
    }
  }
  return null
}

function checkFileSystemAccess(patch: string, file: string): Finding | null {
  const fsPatterns = [
    { re: /require\(['"]fs['"]\)/g },
    { re: /\.readFileSync\(/g },
    { re: /\.writeFileSync\(/g },
    { re: /\.unlinkSync\(/g },
    { re: /\.readdirSync\(/g },
  ]
  for (const { re } of fsPatterns) {
    re.lastIndex = 0
    const m = re.exec(patch)
    if (m) {
      return {
        severity: 'medium',
        category: 'code',
        title: 'File system access',
        description: 'Reads or writes files on the server. Could be used for data exfiltration or overwriting critical files',
        file,
        code: extractSnippet(patch, m.index),
        line: lineFromPatch(patch, m.index),
      }
    }
  }
  return null
}

function checkDynamicRequire(patch: string, file: string): Finding | null {
  const dynamicRe = /require\s*\(\s*(?!['"`])[a-zA-Z_]/g
  const m = dynamicRe.exec(patch)
  if (m) {
    return {
      severity: 'high',
      category: 'supply_chain',
      title: 'Dynamic require() detected',
      description: 'require() with a variable argument enables loading arbitrary modules at runtime, bypassing static dependency analysis',
      file,
      code: extractSnippet(patch, m.index),
      line: lineFromPatch(patch, m.index),
    }
  }
  return null
}

function checkSuspiciousImports(patch: string, file: string): Finding[] {
  const findings: Finding[] = []
  const suspicious = [
    { re: /require\(['"]vm['"]\)/g, label: 'vm module', severity: 'high' as const },
    { re: /require\(['"]worker_threads['"]\)/g, label: 'worker_threads module', severity: 'medium' as const },
    { re: /require\(['"]cluster['"]\)/g, label: 'cluster module', severity: 'low' as const },
    { re: /require\(['"]dgram['"]\)/g, label: 'dgram (raw UDP) module', severity: 'medium' as const },
    { re: /require\(['"]net['"]\)/g, label: 'net (raw TCP) module', severity: 'medium' as const },
  ]
  for (const { re, label, severity } of suspicious) {
    re.lastIndex = 0
    const m = re.exec(patch)
    if (m) {
      findings.push({
        severity,
        category: 'code',
        title: `Suspicious module import: ${label}`,
        description: `Imports ${label}, which can be used for sandbox escape, IPC abuse, or raw network access`,
        file,
        code: extractSnippet(patch, m.index),
        line: lineFromPatch(patch, m.index),
      })
    }
  }
  return findings
}

function checkSecrets(patch: string, file: string): Finding[] {
  const findings: Finding[] = []
  for (const { regex, label } of SECRET_PATTERNS) {
    regex.lastIndex = 0
    const m = regex.exec(patch)
    if (m) {
      findings.push({
        severity: 'high',
        category: 'secret',
        title: 'Hardcoded secret detected',
        description: `${label} found in diff`,
        file,
        code: extractSnippet(patch, m.index).slice(0, 80),
        line: lineFromPatch(patch, m.index),
      })
    }
  }
  return findings
}

function checkPullRequestTarget(patch: string, file: string): Finding | null {
  const idx = patch.indexOf('pull_request_target')
  if (idx !== -1) {
    return {
      severity: 'critical',
      category: 'workflow',
      title: 'pull_request_target trigger detected',
      description: 'This trigger runs with full CI/CD privileges and is the #1 vector for supply chain attacks (used in tj-actions, Ultralytics, and others)',
      file,
      code: extractSnippet(patch, idx),
      line: lineFromPatch(patch, idx),
    }
  }
  return null
}

function checkWriteAll(patch: string, file: string): Finding | null {
  const patterns = ['write-all', 'contents: write', 'permissions: write-all']
  for (const p of patterns) {
    const idx = patch.indexOf(p)
    if (idx !== -1) {
      return {
        severity: 'high',
        category: 'workflow',
        title: 'Excessive CI permissions',
        description: 'write-all or contents:write gives the workflow unnecessary write access. Consider read-only permissions where possible',
        file,
        code: extractSnippet(patch, idx),
        line: lineFromPatch(patch, idx),
      }
    }
  }
  return null
}

function checkMutableActionRefs(patch: string, file: string): Finding[] {
  const findings: Finding[] = []
  const actionRefRegex = /uses:\s+([a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+)@(v?\d+(?:\.\d+)?(?:\.\d+)?|[a-zA-Z]+)$/gm
  let match
  while ((match = actionRefRegex.exec(patch)) !== null) {
    const action = match[1]
    const ref = match[2]
    if (/^v?\d+$/.test(ref) || /^[a-zA-Z]+$/.test(ref)) {
      findings.push({
        severity: 'medium',
        category: 'dependency',
        title: 'Action pinned to mutable tag',
        description: `${action}@${ref} uses a mutable tag. Pin to a commit SHA for immutability`,
        file,
        code: extractSnippet(patch, match.index),
        line: lineFromPatch(patch, match.index),
      })
    }
  }
  return findings
}

function checkSecretsInEnv(patch: string, file: string): Finding | null {
  const idx = patch.indexOf('${{ secrets.')
  if (idx !== -1 && (patch.includes('env:') || patch.includes('env:'))) {
    return {
      severity: 'high',
      category: 'secret',
      title: 'Secret exposed in CI environment',
      description: 'A secret is passed to the environment and may be leaked by malicious actions or steps',
      file,
      code: extractSnippet(patch, idx),
      line: lineFromPatch(patch, idx),
    }
  }
  return null
}

function checkEnvFile(patch: string, file: string): Finding | null {
  if (/\.env(\.[a-zA-Z]+)?$/.test(file)) {
    return {
      severity: 'medium',
      category: 'config',
      title: 'Environment file committed',
      description: `${file} may contain secrets or configuration not meant for version control`,
      file,
    }
  }
  return null
}

function checkBinaryFile(file: string, additions: number, patch: string): Finding | null {
  const binaryExts = ['.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.jar', '.pyc', '.whl']
  const ext = file.toLowerCase().slice(file.lastIndexOf('.'))
  if (binaryExts.includes(ext)) {
    return {
      severity: 'medium',
      category: 'dependency',
      title: 'Binary file added',
      description: `${file} is a binary file. Verify its origin and necessity`,
      file,
    }
  }
  return null
}

function checkLargeFile(file: string, additions: number, patch: string): Finding | null {
  if (additions > 500) {
    return {
      severity: 'low',
      category: 'config',
      title: 'Large file added',
      description: `${file} adds ${additions} lines. Large files should be reviewed carefully`,
      file,
    }
  }
  return null
}

export function runRules(files: PRFile[], prNumber?: number, owner?: string, repo?: string, sha?: string): Finding[] {
  resetFindingCounter()
  const findings: Finding[] = []
  for (const file of files) {
    const patch = file.patch || ''
    const isWorkflow = file.filename.startsWith('.github/workflows/') && (file.filename.endsWith('.yml') || file.filename.endsWith('.yaml'))

    // Secret detection
    findings.push(...checkSecrets(patch, file.filename))

    // SAST code analysis (always)
    const unsafeEval = checkUnsafeEval(patch, file.filename)
    if (unsafeEval) findings.push(unsafeEval)
    const obfuscation = checkObfuscation(patch, file.filename)
    if (obfuscation) findings.push(obfuscation)
    const envAccess = checkEnvAccess(patch, file.filename)
    if (envAccess) findings.push(envAccess)
    findings.push(...checkNetworkExfil(patch, file.filename))
    const osCmd = checkOSCommand(patch, file.filename)
    if (osCmd) findings.push(osCmd)
    const fsAccess = checkFileSystemAccess(patch, file.filename)
    if (fsAccess) findings.push(fsAccess)
    const dynReq = checkDynamicRequire(patch, file.filename)
    if (dynReq) findings.push(dynReq)
    findings.push(...checkSuspiciousImports(patch, file.filename))

    if (isWorkflow) {
      const prt = checkPullRequestTarget(patch, file.filename)
      if (prt) findings.push(prt)
      const wa = checkWriteAll(patch, file.filename)
      if (wa) findings.push(wa)
      const sEnv = checkSecretsInEnv(patch, file.filename)
      if (sEnv) findings.push(sEnv)
    }

    findings.push(...checkMutableActionRefs(patch, file.filename))

    const envF = checkEnvFile(patch, file.filename)
    if (envF) findings.push(envF)

    const bin = checkBinaryFile(file.filename, file.additions, patch)
    if (bin) findings.push(bin)

    const large = checkLargeFile(file.filename, file.additions, patch)
    if (large) findings.push(large)
  }

  // Attach PR URL to findings that have line numbers
  if (prNumber && owner && repo && sha) {
    for (const f of findings) {
      if (f.file && f.line != null) {
        f.prUrl = `https://github.com/${owner}/${repo}/blob/${sha}/${f.file}#L${f.line}`
      }
    }
  }
  return findings.map(enrichFinding)
}

export function calculateScore(findings: Finding[]): { score: number; critical: number; high: number; medium: number; low: number } {
  let score = 0
  let critical = 0; let high = 0; let medium = 0; let low = 0
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': score += 20; critical++; break
      case 'high': score += 10; high++; break
      case 'medium': score += 4; medium++; break
      case 'low': score += 1; low++; break
    }
  }
  return { score, critical, high, medium, low }
}
