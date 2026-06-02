import { execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { ToolDef } from './providers/base.js';

export interface Tool {
  name: string;
  description: string;
  parameters: ToolDef['parameters'];
  run: (args: Record<string, string>) => string;
}

// Resolve sentinel binary safely — no shell interpolation
function sentinelCmd(): { cmd: string; args: string[] } {
  const argv1 = process.argv[1] || '';
  if (process.argv[0].endsWith('node.exe') || process.argv[0].endsWith('node')) {
    const script = argv1.replace(/main\.js$/, '') + 'main.js';
    return { cmd: process.argv[0], args: [path.resolve(script)] };
  }
  return { cmd: 'sentinel', args: [] };
}

function runSentinel(subcmd: string, ...params: string[]): string {
  const { cmd, args } = sentinelCmd();
  try {
    return execFileSync(cmd, [...args, subcmd, ...params], {
      timeout: 60000,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    }).trim();
  } catch (e: any) {
    return e.stdout?.trim() || e.stderr?.trim() || e.message;
  }
}

function runGh(ghArgs: string[]): string {
  try {
    return execFileSync('gh', ghArgs, {
      timeout: 30000,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    }).trim();
  } catch (e: any) {
    return e.stdout?.trim() || e.stderr?.trim() || e.message;
  }
}

function sanitizePath(input: string): string {
  return input.replace(/[^a-zA-Z0-9_\-./\\:]/g, '').replace(/\.\./g, '').trim();
}

function sanitizePkg(input: string): string {
  const match = input.match(/^@?[a-zA-Z0-9._\-\/]+(@\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?)?$/);
  return match ? match[0] : input.replace(/[^a-zA-Z0-9._\-@\/]/g, '');
}

export const tools: Tool[] = [
  {
    name: 'scan',
    description: 'Scan a directory or file for security threats using LiteScanner (30 SAST rules including secrets, eval, network, env access)',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File or directory path to scan (default: current dir)' },
      },
      required: [],
    },
    run: ({ path: p }) => {
      const safePath = p ? sanitizePath(p) : '.';
      return runSentinel('scan', safePath, '--json');
    },
  },
  {
    name: 'verify-pkg',
    description: 'Audit an npm package via npm pack (zero-install) — detects typosquatting, secret leaks, hardcoded credentials, and supply chain threats in the tarball',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'npm package name to audit (e.g. axios, lodash)' },
      },
      required: ['package'],
    },
    run: ({ package: pkg }) => {
      const safePkg = sanitizePkg(pkg || '');
      if (!safePkg) return 'Error: invalid package name';
      return runSentinel('verify-pkg', safePkg);
    },
  },
  {
    name: 'doctor',
    description: 'System health check for npm dependencies in a project — scans for known vulnerabilities, capability risks, and outdated packages',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Project path to scan (default: current dir)' },
        deep: { type: 'string', enum: ['--deep', ''], description: 'Pass --deep for full dependency tree scan' },
      },
      required: [],
    },
    run: ({ path: p, deep }) => {
      const safePath = p ? sanitizePath(p) : '.';
      const args = deep === '--deep' ? ['--deep', safePath] : [safePath];
      return runSentinel('doctor', ...args);
    },
  },
  {
    name: 'check-classified',
    description: 'Check staged files in a git repo against the classified documents database. Blocks commits when classified files are staged.',
    parameters: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Git repository path (default: current dir)' },
      },
      required: [],
    },
    run: ({ path: p }) => {
      const safePath = p ? sanitizePath(p) : '.';
      return runSentinel('check-classified', safePath);
    },
  },
  {
    name: 'integrity',
    description: 'Verify Sentinel host integrity — checks code hash, PATH poisoning, vault integrity, clock anomalies, signed manifest, and persistent integrity chain',
    parameters: {
      type: 'object',
      properties: {},
      required: [],
    },
    run: () => {
      return runSentinel('integrity');
    },
  },
  {
    name: 'memory',
    description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Action like --findings, --sessions, --threats' },
        query: { type: 'string', description: 'Optional search term' },
      },
      required: [],
    },
    run: ({ action, query }) => {
      const safeAction = action ? sanitizePath(action) : '';
      const safeQuery = query ? sanitizePath(query) : '';
      return runSentinel('memory', safeAction, safeQuery);
    },
  },
  // --- GitHub PR & Repo tools (Phase 2) ---
  {
    name: 'gh-pr-list',
    description: 'List open pull requests in the current GitHub repository. Returns PR number, title, author, and status.',
    parameters: {
      type: 'object',
      properties: {
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
        limit: { type: 'string', description: 'Max PRs to return (default: 10)' },
        state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'PR state filter' },
      },
      required: [],
    },
    run: ({ repo, limit, state }) => {
      const args = ['pr', 'list'];
      if (repo && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repo)) args.push('--repo', repo);
      args.push('--limit', String(Math.min(Math.max(parseInt(limit) || 10, 1), 100)));
      args.push('--state', state === 'closed' ? 'closed' : state === 'all' ? 'all' : 'open');
      args.push('--json', 'number,title,author,headRefName,baseRefName,createdAt,state');
      return runGh(args);
    },
  },
  {
    name: 'gh-pr-view',
    description: 'View detailed information about a specific pull request: diff stats, changed files, labels, reviewers, and CI status.',
    parameters: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'PR number to view' },
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
      },
      required: ['number'],
    },
    run: ({ number, repo }) => {
      const prNum = parseInt(number);
      if (isNaN(prNum) || prNum < 1) return 'Error: invalid PR number';
      const args = ['pr', 'view', String(prNum)];
      if (repo && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repo)) args.push('--repo', repo);
      args.push('--json', 'title,body,author,state,mergeable,reviews,additions,deletions,files,labels,createdAt,closedAt,headRepository,baseRepository');
      return runGh(args);
    },
  },
  {
    name: 'gh-pr-diff',
    description: 'Get the full diff of a pull request. Returns the raw diff output which can be piped directly into sentinel scan for SAST analysis.',
    parameters: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'PR number to get diff from' },
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
      },
      required: ['number'],
    },
    run: ({ number, repo }) => {
      const prNum = parseInt(number);
      if (isNaN(prNum) || prNum < 1) return 'Error: invalid PR number';
      const args = ['pr', 'diff', String(prNum)];
      if (repo && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repo)) args.push('--repo', repo);
      try {
        return execFileSync('gh', args, {
          timeout: 30000, encoding: 'utf-8',
          maxBuffer: 50 * 1024 * 1024, windowsHide: true,
        }).trim();
      } catch (e: any) {
        return e.stdout?.trim() || e.stderr?.trim() || e.message;
      }
    },
  },
  {
    name: 'gh-pr-comment',
    description: 'Post a comment on a pull request. Use to deliver security audit results directly on the PR.',
    parameters: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'PR number to comment on' },
        body: { type: 'string', description: 'Comment body text' },
        repo: { type: 'string', description: 'Repo in format owner/name (default: current dir repo)' },
      },
      required: ['number', 'body'],
    },
    run: ({ number, body, repo }) => {
      const prNum = parseInt(number);
      if (isNaN(prNum) || prNum < 1) return 'Error: invalid PR number';
      if (!body) return 'Error: comment body is required';

      // Use OS temp dir with random name — safe from symlink attacks
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-gh-'));
      const tempFile = path.join(tmpDir, `comment_${prNum}.md`);
      try {
        fs.writeFileSync(tempFile, body, 'utf-8');
        const args = ['pr', 'comment', String(prNum)];
        if (repo && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(repo)) args.push('--repo', repo);
        args.push('--body-file', tempFile);
        return execFileSync('gh', args, {
          timeout: 15000, encoding: 'utf-8', windowsHide: true,
        }).trim();
      } catch (e: any) {
        return e.stdout?.trim() || e.stderr?.trim() || e.message;
      } finally {
        try { fs.unlinkSync(tempFile); } catch {}
        try { fs.rmdirSync(tmpDir); } catch {}
      }
    },
  },
  {
    name: 'gh-repo-list',
    description: 'List GitHub repositories for the authenticated user or organization. Shows name, visibility, and description.',
    parameters: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'User or organization name (default: authenticated user)' },
        limit: { type: 'string', description: 'Max repos to return (default: 20)' },
      },
      required: [],
    },
    run: ({ owner, limit }) => {
      const args = ['repo', 'list'];
      const safeOwner = owner ? owner.replace(/[^a-zA-Z0-9_.-]/g, '') : '';
      if (safeOwner) args.push('--owner', safeOwner);
      args.push('--limit', String(Math.min(Math.max(parseInt(limit) || 20, 1), 100)));
      args.push('--json', 'name,owner,visibility,description,url,isFork');
      return runGh(args);
    },
  },
  // --- Machine Analysis Tools (Phase 3) ---
  {
    name: 'machine-classify',
    description: 'Classify a file against the classified documents database. Detects if a file contains classified/sensitive content.',
    parameters: {
      type: 'object',
      properties: {
        file: { type: 'string', description: 'File path to classify' },
      },
      required: ['file'],
    },
    run: ({ file }) => {
      const safeFile = sanitizePath(file || '');
      if (!safeFile) return 'Error: invalid file path';
      return runSentinel('classify', safeFile);
    },
  },
  {
    name: 'machine-integrity',
    description: 'Run Sentinel integrity check on the host system — verifies code hash, PATH, vault, clock, and manifest integrity.',
    parameters: {
      type: 'object',
      properties: {},
      required: [],
    },
    run: () => runSentinel('integrity'),
  },
  {
    name: 'machine-memory',
    description: 'Query the Signal Vault (local SQLite) for past scan results, findings, threat correlations, and session history.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Action: --findings, --sessions, --threats, or custom query' },
        query: { type: 'string', description: 'Optional search term' },
      },
      required: [],
    },
    run: ({ action, query }) => {
      const safeAction = action ? sanitizePath(action) : '';
      const safeQuery = query ? sanitizePath(query) : '';
      return runSentinel('memory', safeAction, safeQuery);
    },
  },
  // --- Package Download & Install Workflow ---
  {
    name: 'download-verify-pkg',
    description: 'Download an npm package to a temp directory and scan it with sentinel. Does NOT install. Reports typosquatting, secrets, malicious patterns before any installation.',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'npm package name to download and analyze' },
      },
      required: ['package'],
    },
    run: ({ package: pkg }) => {
      const safePkg = sanitizePkg(pkg || '');
      if (!safePkg) return 'Error: invalid package name';

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-dl-'));
      try {
        const packResult = execFileSync('npm', ['pack', safePkg, '--pack-destination', tmpDir], {
          timeout: 30000,
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          windowsHide: true,
        }).trim();

        const tarball = packResult.split('\n').pop()?.trim() || '';
        const tarballPath = path.join(tmpDir, tarball);

        if (!fs.existsSync(tarballPath)) {
          return `Error: tarball not found. npm output: ${packResult}`;
        }

        const scanResult = runSentinel('verify-pkg', tarballPath);

        return [
          `Package: ${safePkg}`,
          `Tarball: ${tarball}`,
          `Size: ${(fs.statSync(tarballPath).size / 1024).toFixed(1)} KB`,
          '',
          '=== Analysis ===',
          scanResult,
        ].join('\n');
      } catch (e: any) {
        return `Error: ${e.message}`;
      } finally {
        try {
          const files = fs.readdirSync(tmpDir);
          for (const f of files) {
            try { fs.unlinkSync(path.join(tmpDir, f)); } catch {}
          }
          try { fs.rmdirSync(tmpDir); } catch {}
        } catch {}
      }
    },
  },
  {
    name: 'install-pkg',
    description: 'Install an npm package. ONLY use after verifying with download-verify-pkg AND after the user explicitly asks to install.',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'npm package name to install' },
        global: { type: 'string', enum: ['--global', ''], description: '--global for global install' },
      },
      required: ['package'],
    },
    run: ({ package: pkg, global }) => {
      const safePkg = sanitizePkg(pkg || '');
      if (!safePkg) return 'Error: invalid package name';
      try {
        const args = global === '--global' ? ['install', '--global', safePkg] : ['install', safePkg];
        return execFileSync('npm', args, {
          timeout: 60000,
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          windowsHide: true,
        }).trim();
      } catch (e: any) {
        return e.stdout?.trim() || e.stderr?.trim() || e.message;
      }
    },
  },
  {
    name: 'remove-pkg',
    description: 'Remove an installed npm package. Use when a package is found to be malicious or unwanted.',
    parameters: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'npm package name to remove' },
        global: { type: 'string', enum: ['--global', ''], description: '--global if globally installed' },
      },
      required: ['package'],
    },
    run: ({ package: pkg, global }) => {
      const safePkg = sanitizePkg(pkg || '');
      if (!safePkg) return 'Error: invalid package name';
      try {
        const args = global === '--global' ? ['uninstall', '--global', safePkg] : ['uninstall', safePkg];
        return execFileSync('npm', args, {
          timeout: 30000,
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024,
          windowsHide: true,
        }).trim();
      } catch (e: any) {
        return e.stdout?.trim() || e.stderr?.trim() || e.message;
      }
    },
  },
];

export function getToolDefs(): ToolDef[] {
  return tools.map(t => ({
    name: t.name,
    description: t.description,
    parameters: t.parameters,
  }));
}

export function runTool(name: string, args: Record<string, string>): string {
  const tool = tools.find(t => t.name === name);
  if (!tool) return `Unknown tool: ${name}`;
  return tool.run(args);
}
