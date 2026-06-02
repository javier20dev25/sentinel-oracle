import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockExecFileSync = vi.hoisted(() => vi.fn());
const mockCreateInterface = vi.hoisted(() => vi.fn());

vi.mock('child_process', () => ({
  execFileSync: mockExecFileSync,
}));

vi.mock('readline', () => ({
  createInterface: mockCreateInterface,
}));

import { checkGitHubLogin } from './github';

beforeEach(() => {
  vi.clearAllMocks();
  (process.stdout as any).write = vi.fn();
});

describe('checkGitHubLogin', () => {
  it('returns true when gh is installed and logged in', async () => {
    mockExecFileSync.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === 'gh' && args[0] === '--version') return 'gh version 2.0.0';
      if (cmd === 'gh' && args[0] === 'auth' && args[1] === 'status') {
        return 'Logged in to github.com as testuser (token)';
      }
      return '';
    });

    const result = await checkGitHubLogin();
    expect(result).toBe(true);
  });

  it('returns false when gh is not installed', async () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('not found');
    });

    const result = await checkGitHubLogin();
    expect(result).toBe(false);
  });

  it('returns false when gh is installed but not logged in (user skips)', async () => {
    let callCount = 0;
    mockExecFileSync.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return 'gh version 2.0.0';
      throw new Error('Not logged in');
    });

    const mockRl = {
      question: vi.fn((_q: string, cb: (a: string) => void) => cb('2')),
      close: vi.fn(),
    };
    mockCreateInterface.mockReturnValue(mockRl);

    const result = await checkGitHubLogin();
    expect(result).toBe(false);
  });

  it('gracefully handles gh --version failure', async () => {
    mockExecFileSync.mockImplementation(() => {
      throw new Error('ENOENT');
    });

    const result = await checkGitHubLogin();
    expect(result).toBe(false);
  });

  it('returns false when gh is installed but not logged in (user tries login)', async () => {
    let callCount = 0;
    mockExecFileSync.mockImplementation(() => {
      callCount++;
      if (callCount === 1) return 'gh version 2.0.0';
      if (callCount === 2) throw new Error('Not logged in');
      throw new Error('Login failed');
    });

    const mockRl = {
      question: vi.fn((_q: string, cb: (a: string) => void) => cb('1')),
      close: vi.fn(),
    };
    mockCreateInterface.mockReturnValue(mockRl);

    const result = await checkGitHubLogin();
    expect(result).toBe(false);
  });
});
