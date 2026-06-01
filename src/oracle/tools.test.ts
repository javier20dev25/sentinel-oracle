import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockExecFileSync = vi.hoisted(() => vi.fn());
const mockExistsSync = vi.hoisted(() => vi.fn());
const mockMkdtempSync = vi.hoisted(() => vi.fn());
const mockWriteFileSync = vi.hoisted(() => vi.fn());
const mockReaddirSync = vi.hoisted(() => vi.fn());
const mockUnlinkSync = vi.hoisted(() => vi.fn());
const mockRmdirSync = vi.hoisted(() => vi.fn());
const mockStatSync = vi.hoisted(() => vi.fn());
const mockTmpdir = vi.hoisted(() => vi.fn(() => '/tmp'));
const mockJoin = vi.hoisted(() => vi.fn((...args: string[]) => args.join('/')));
const mockResolve = vi.hoisted(() => vi.fn((p: string) => p));

vi.mock('child_process', () => ({
  execFileSync: mockExecFileSync,
}));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
  mkdtempSync: mockMkdtempSync,
  writeFileSync: mockWriteFileSync,
  readdirSync: mockReaddirSync,
  unlinkSync: mockUnlinkSync,
  rmdirSync: mockRmdirSync,
  statSync: mockStatSync,
}));

vi.mock('os', () => ({
  tmpdir: mockTmpdir,
}));

vi.mock('path', () => ({
  join: mockJoin,
  resolve: mockResolve,
}));

import { getToolDefs, runTool, tools } from './tools';

beforeEach(() => {
  vi.clearAllMocks();
  // Default: node process
  vi.stubGlobal('process', {
    ...process,
    argv: ['node', 'C:\\sentinel\\main.js'],
  });
  mockExecFileSync.mockReturnValue('ok');
  mockExistsSync.mockReturnValue(true);
  mockMkdtempSync.mockReturnValue('/tmp/sentinel-test-123');
  mockStatSync.mockReturnValue({ size: 1024 });
  mockReaddirSync.mockReturnValue([]);
});

// ─── getToolDefs ──────────────────────────────────────────────

describe('getToolDefs', () => {
  it('returns an array of tool definitions', () => {
    const defs = getToolDefs();
    expect(Array.isArray(defs)).toBe(true);
    expect(defs.length).toBeGreaterThan(0);
  });

  it('each tool has name, description, and parameters', () => {
    const defs = getToolDefs();
    for (const t of defs) {
      expect(t).toHaveProperty('name');
      expect(t).toHaveProperty('description');
      expect(t).toHaveProperty('parameters');
      expect(t.parameters).toHaveProperty('type', 'object');
      expect(t.parameters).toHaveProperty('properties');
    }
  });

  it('tool parameters have correct property structure', () => {
    const defs = getToolDefs();
    for (const t of defs) {
      for (const [key, prop] of Object.entries(t.parameters.properties)) {
        expect(prop).toHaveProperty('type');
      }
    }
  });
});

// ─── tools array ──────────────────────────────────────────────

describe('tools array', () => {
  const requiredTools = [
    'scan', 'verify-pkg', 'doctor', 'check-classified', 'integrity', 'memory',
    'gh-pr-list', 'gh-pr-view', 'gh-pr-diff', 'gh-pr-comment', 'gh-repo-list',
    'machine-classify', 'machine-integrity', 'machine-memory',
    'download-verify-pkg', 'install-pkg', 'remove-pkg',
  ];

  for (const name of requiredTools) {
    it(`includes tool "${name}"`, () => {
      const tool = tools.find(t => t.name === name);
      expect(tool).toBeDefined();
      expect(tool!.name).toBe(name);
      expect(typeof tool!.description).toBe('string');
      expect(tool!.description.length).toBeGreaterThan(0);
      expect(typeof tool!.run).toBe('function');
    });
  }

  it('each tool has a run function that returns a string', () => {
    for (const t of tools) {
      expect(typeof t.run).toBe('function');
    }
  });
});

// ─── runTool ──────────────────────────────────────────────────

describe('runTool', () => {
  it('returns error message for unknown tool', () => {
    const result = runTool('nonexistent-tool', {});
    expect(result).toBe('Unknown tool: nonexistent-tool');
  });

  it('calls the tool run function for known tools', () => {
    const spy = vi.spyOn(tools.find(t => t.name === 'integrity')!, 'run');
    runTool('integrity', {});
    expect(spy).toHaveBeenCalledWith({});
  });
});

// ─── scan tool ────────────────────────────────────────────────

describe('scan tool', () => {
  it('executes scan with sanitized path', () => {
    const tool = tools.find(t => t.name === 'scan')!;
    tool.run({ path: './src' });
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('scan');
    expect(args[1]).toContain('./src');
    expect(args[1]).toContain('--json');
  });

  it('uses default path "." when no path provided', () => {
    const tool = tools.find(t => t.name === 'scan')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('.');
  });

  it('sanitizes dangerous characters from path', () => {
    const tool = tools.find(t => t.name === 'scan')!;
    tool.run({ path: 'foo; rm -rf /' });
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    const pathArg = args[1][2];
    expect(pathArg).toContain('foo');
    expect(pathArg).not.toContain(';');
    expect(pathArg).not.toContain(' ');
  });
});

// ─── verify-pkg tool ──────────────────────────────────────────

describe('verify-pkg tool', () => {
  it('calls runSentinel with sanitized package name', () => {
    const tool = tools.find(t => t.name === 'verify-pkg')!;
    tool.run({ package: 'axios' });
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('verify-pkg');
    expect(args[1]).toContain('axios');
  });

  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'verify-pkg')!;
    // Empty package should fail sanitizePkg
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });
});

// ─── gh-pr-tools ──────────────────────────────────────────────

describe('gh-pr-list tool', () => {
  it('executes gh pr list with default args', () => {
    const tool = tools.find(t => t.name === 'gh-pr-list')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'list']), expect.any(Object),
    );
  });

  it('includes --repo flag when valid repo provided', () => {
    const tool = tools.find(t => t.name === 'gh-pr-list')!;
    tool.run({ repo: 'owner/repo' });
    const call = mockExecFileSync.mock.calls.find((c: any[]) => c[0] === 'gh');
    expect(call[1]).toContain('--repo');
    expect(call[1]).toContain('owner/repo');
  });
});

describe('gh-pr-view tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-view')!;
    const result = tool.run({ number: 'abc' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('executes gh pr view with valid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-view')!;
    tool.run({ number: '42' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'view', '42']), expect.any(Object),
    );
  });
});

describe('gh-pr-diff tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    const result = tool.run({ number: 'abc' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('executes gh pr diff with valid PR number', () => {
    mockExecFileSync.mockReturnValue('diff output');
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    tool.run({ number: '1' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'diff', '1']), expect.any(Object),
    );
  });

  it('handles gh error gracefully', () => {
    mockExecFileSync.mockImplementation(() => { throw { stdout: 'Not found', stderr: '' }; });
    const tool = tools.find(t => t.name === 'gh-pr-diff')!;
    const result = tool.run({ number: '1' });
    expect(result).toBe('Not found');
  });
});

describe('gh-pr-comment tool', () => {
  it('returns error for invalid PR number', () => {
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    const result = tool.run({ number: 'abc', body: 'test' });
    expect(result).toBe('Error: invalid PR number');
  });

  it('returns error for missing body', () => {
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    const result = tool.run({ number: '1', body: '' });
    expect(result).toBe('Error: comment body is required');
  });

  it('writes body to temp file and calls gh pr comment', () => {
    mockExistsSync.mockReturnValue(true);
    const tool = tools.find(t => t.name === 'gh-pr-comment')!;
    const result = tool.run({ number: '1', body: 'LGTM' });
    expect(mockWriteFileSync).toHaveBeenCalled();
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['pr', 'comment', '1', '--body-file']), expect.any(Object),
    );
  });
});

describe('gh-repo-list tool', () => {
  it('executes gh repo list with default limit', () => {
    const tool = tools.find(t => t.name === 'gh-repo-list')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'gh', expect.arrayContaining(['repo', 'list', '--limit', '20']), expect.any(Object),
    );
  });

  it('sanitizes owner name', () => {
    const tool = tools.find(t => t.name === 'gh-repo-list')!;
    tool.run({ owner: 'my-org; rm -rf' });
    const call = mockExecFileSync.mock.calls.find((c: any[]) => c[0] === 'gh');
    const args = call[1];
    expect(args).toContain('--owner');
    const ownerIdx = args.indexOf('--owner');
    expect(ownerIdx).toBeGreaterThanOrEqual(0);
    const ownerVal = args[ownerIdx + 1];
    expect(ownerVal).toContain('my-org');
    expect(ownerVal).not.toContain(';');
    expect(ownerVal).not.toContain(' ');
  });
});

// ─── machine tools ────────────────────────────────────────────

describe('machine-classify tool', () => {
  it('returns error for empty file path', () => {
    const tool = tools.find(t => t.name === 'machine-classify')!;
    const result = tool.run({ file: '' });
    expect(result).toBe('Error: invalid file path');
  });

  it('calls sentinel classify with sanitized file', () => {
    const tool = tools.find(t => t.name === 'machine-classify')!;
    tool.run({ file: 'secret.txt' });
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('classify');
    expect(args[1]).toContain('secret.txt');
  });
});

describe('machine-integrity tool', () => {
  it('calls sentinel integrity', () => {
    const tool = tools.find(t => t.name === 'machine-integrity')!;
    tool.run({});
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('integrity');
  });
});

describe('machine-memory tool', () => {
  it('calls sentinel memory with action and query', () => {
    const tool = tools.find(t => t.name === 'machine-memory')!;
    tool.run({ action: '--findings', query: 'secret' });
    expect(mockExecFileSync).toHaveBeenCalled();
    const args = mockExecFileSync.mock.calls[0];
    expect(args[1]).toContain('memory');
    expect(args[1]).toContain('--findings');
    expect(args[1]).toContain('secret');
  });
});

// ─── download-verify-pkg tool ─────────────────────────────────

describe('download-verify-pkg tool', () => {
  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('downloads and scans a package', () => {
    mockExecFileSync
      .mockReturnValueOnce('package-1.0.0.tgz\n')
      .mockReturnValueOnce('No threats found');
    mockExistsSync.mockReturnValue(true);

    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = tool.run({ package: 'safe-pkg' });

    expect(result).toContain('safe-pkg');
    expect(result).toContain('package-1.0.0.tgz');
    expect(result).toContain('Analysis');
  });

  it('handles pack failure', () => {
    mockExecFileSync
      .mockReturnValueOnce('')
      .mockReturnValueOnce('');
    mockExistsSync.mockReturnValue(false);

    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = tool.run({ package: 'safe-pkg' });

    expect(result).toContain('tarball not found');
  });

  it('handles pack failure', () => {
    mockExecFileSync
      .mockReturnValueOnce(Buffer.from(''))
      .mockReturnValueOnce(Buffer.from(''));
    mockExistsSync.mockReturnValue(false);

    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = tool.run({ package: 'safe-pkg' });

    expect(result).toContain('tarball not found');
  });

  it('handles execution errors', () => {
    mockExecFileSync.mockImplementation(() => { throw new Error('network error'); });

    const tool = tools.find(t => t.name === 'download-verify-pkg')!;
    const result = tool.run({ package: 'safe-pkg' });

    expect(result).toContain('Error');
  });
});

// ─── install-pkg / remove-pkg ─────────────────────────────────

describe('install-pkg tool', () => {
  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('installs package with npm install', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    tool.run({ package: 'lodash' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'npm', expect.arrayContaining(['install', 'lodash']), expect.any(Object),
    );
  });

  it('installs globally with --global flag', () => {
    const tool = tools.find(t => t.name === 'install-pkg')!;
    tool.run({ package: 'nodemon', global: '--global' });
    const call = mockExecFileSync.mock.calls.find((c: any[]) => c[0] === 'npm');
    expect(call[1]).toContain('--global');
  });
});

describe('remove-pkg tool', () => {
  it('returns error for invalid package name', () => {
    const tool = tools.find(t => t.name === 'remove-pkg')!;
    const result = tool.run({ package: '' });
    expect(result).toBe('Error: invalid package name');
  });

  it('removes package with npm uninstall', () => {
    const tool = tools.find(t => t.name === 'remove-pkg')!;
    tool.run({ package: 'bad-pkg' });
    expect(mockExecFileSync).toHaveBeenCalledWith(
      'npm', expect.arrayContaining(['uninstall', 'bad-pkg']), expect.any(Object),
    );
  });
});

// ─── sentinelCmd resolution ──────────────────────────────────

describe('sentinelCmd resolution (via scan tool)', () => {
  it('resolves script path when running from node', () => {
    vi.stubGlobal('process', {
      ...process,
      argv: ['node', '/app/dist/main.js'],
    });

    const tool = tools.find(t => t.name === 'scan')!;
    tool.run({ path: '.' });

    const call = mockExecFileSync.mock.calls[0];
    expect(call[0]).toBe('node');
    expect(call[1][0]).toContain('main.js');
    expect(call[1][1]).toBe('scan');
    vi.unstubAllGlobals();
  });
});

// ─── error handling ───────────────────────────────────────────

describe('error handling', () => {
  it('runSentinel returns error message on failure', () => {
    mockExecFileSync.mockImplementation(() => {
      const err: any = new Error('Command failed');
      err.stdout = 'node error';
      err.stderr = '';
      throw err;
    });

    const tool = tools.find(t => t.name === 'scan')!;
    const result = tool.run({ path: '.' });
    expect(result).toBe('node error');
  });

  it('runGh returns error message on gh failure', () => {
    mockExecFileSync.mockImplementation(() => {
      const err: any = new Error('gh error');
      err.stdout = '';
      err.stderr = 'gh not logged in';
      throw err;
    });

    const tool = tools.find(t => t.name === 'gh-pr-list')!;
    const result = tool.run({});
    expect(result).toBe('gh not logged in');
  });
});
