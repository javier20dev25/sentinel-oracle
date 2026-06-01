import { execSync, spawn } from 'child_process';

export interface GuardReport {
  passed: boolean;
  machine: { status: string; detail: string };
  gh: { status: string; detail: string };
  auth: { status: string; detail: string };
  remote: { status: string; detail: string };
  repo: { status: string; detail: string };
}

function run(cmd: string): { ok: boolean; out: string; err: string } {
  try {
    const out = execSync(cmd, { timeout: 10000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    return { ok: true, out: out.trim(), err: '' };
  } catch (e: any) {
    return { ok: false, out: e.stdout?.trim() || '', err: e.stderr?.trim() || e.message };
  }
}

export function runGuard(): GuardReport {
  const report: GuardReport = {
    passed: false,
    machine: { status: '❌', detail: '' },
    gh: { status: '❌', detail: '' },
    auth: { status: '❌', detail: '' },
    remote: { status: '❌', detail: '' },
    repo: { status: '❌', detail: '' },
  };

  // 1. Machine check — OS + Node
  const osCheck = run('node -e "console.log(process.version)"');
  if (osCheck.ok) {
    report.machine = { status: '✅', detail: `Node.js ${osCheck.out} | ${process.platform} ${process.arch}` };
  } else {
    report.machine = { status: '❌', detail: 'Node.js not found' };
    return report;
  }

  // 2. gh CLI installed
  const ghCheck = run('gh --version');
  if (ghCheck.ok) {
    const ver = ghCheck.out.split('\n')[0] || ghCheck.out;
    report.gh = { status: '✅', detail: ver };
  } else {
    report.gh = { status: '❌', detail: 'gh CLI not installed. Install from https://cli.github.com/' };
    return report;
  }

  // 3. gh authenticated
  const authCheck = run('gh auth status 2>&1');
  if (authCheck.ok) {
    const userLine = authCheck.out.split('\n').find(l => l.includes('Logged in'));
    report.auth = { status: '✅', detail: userLine || 'Authenticated' };
  } else {
    report.auth = { status: '❌', detail: 'Not authenticated. Run: gh auth login' };
    return report;
  }

  // 4. Remote URL check (from cwd git repo)
  const remoteCheck = run('git remote get-url origin 2>&1');
  if (remoteCheck.ok) {
    const url = remoteCheck.out;
    if (url.startsWith('https://')) {
      report.remote = { status: '✅', detail: `HTTPS remote: ${url}` };
    } else if (url.startsWith('git@')) {
      report.remote = { status: '⚠️', detail: `SSH remote — no HTTPS verification: ${url}` };
    } else {
      report.remote = { status: '⚠️', detail: `Unknown protocol: ${url}` };
    }
  } else {
    report.remote = { status: '⚠️', detail: 'No git remote "origin" found (not in a repo?)' };
  }

  // 5. Repo access check
  const repoCheck = run('gh repo view --json name,owner 2>&1');
  if (repoCheck.ok) {
    report.repo = { status: '✅', detail: 'Repo accessible via gh' };
  } else {
    report.repo = { status: '⚠️', detail: 'Not in a valid GitHub repo: ' + repoCheck.err.slice(0, 100) };
  }

  report.passed = report.machine.status === '✅' && report.gh.status === '✅' && report.auth.status === '✅';
  return report;
}

export function ghLogin(): Promise<{ success: boolean; username?: string; message?: string }> {
  return new Promise((resolve) => {
    const ghCmd = process.platform === 'win32' ? 'gh.exe' : 'gh';
    const child = spawn(ghCmd, ['auth', 'login', '-w', '-p', 'https', '--skip-ssh-key'], {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let output = '';
    let resolved = false;

    child.stdout?.on('data', (d) => {
      const msg = d.toString();
      output += msg;
      if (msg.toLowerCase().includes('press enter')) {
        child.stdin.write('\n');
      }
    });

    child.stderr?.on('data', (d) => {
      const msg = d.toString();
      output += msg;
      if (msg.toLowerCase().includes('press enter')) {
        child.stdin.write('\n');
      }
    });

    const timeout = setTimeout(() => {
      if (!resolved) {
        child.kill();
        resolve({ success: false, message: 'Authentication timed out after 60 seconds.' });
      }
    }, 60000);

    child.on('close', (code) => {
      clearTimeout(timeout);
      if (resolved) return;
      resolved = true;
      if (code === 0) {
        const auth = runGuard();
        const userLine = auth.auth.detail;
        resolve({ success: true, username: userLine || 'Unknown' });
      } else {
        resolve({ success: false, message: output || 'Login failed. Please run: gh auth login' });
      }
    });

    child.on('error', (err) => {
      clearTimeout(timeout);
      if (resolved) return;
      resolved = true;
      resolve({ success: false, message: err.message });
    });
  });
}

export function formatGuardReport(report: GuardReport): string {
  const lines = [
    '🔐 Guarda de Conexión — Máquina ⇄ gh ⇄ GitHub',
    '',
    `  ${report.machine.status} Máquina:  ${report.machine.detail}`,
    `  ${report.gh.status}     gh CLI:  ${report.gh.detail}`,
    `  ${report.auth.status}     Auth:     ${report.auth.detail}`,
    `  ${report.remote.status}     Remote:   ${report.remote.detail}`,
    `  ${report.repo.status}     Repo:     ${report.repo.detail}`,
    '',
    report.passed
      ? '  ✅ Conexión segura — todo en orden.'
      : '  ❌ Guarda bloqueada — revisá los errores arriba.',
  ];
  return lines.join('\n');
}
