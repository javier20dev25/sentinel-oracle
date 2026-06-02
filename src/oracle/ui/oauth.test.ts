import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';

const mockCreateServer = vi.hoisted(() => vi.fn());
const mockHttpsRequest = vi.hoisted(() => vi.fn());
const mockExecFile = vi.hoisted(() => vi.fn());
const mockExistsSync = vi.hoisted(() => vi.fn(() => false));
const mockMkdirSync = vi.hoisted(() => vi.fn());
const mockWriteFileSync = vi.hoisted(() => vi.fn());
const mockReadFileSync = vi.hoisted(() => vi.fn());
const mockChmodSync = vi.hoisted(() => vi.fn());
const mockUnlinkSync = vi.hoisted(() => vi.fn());
const mockHostname = vi.hoisted(() => vi.fn(() => 'test-machine'));
const mockUserInfo = vi.hoisted(
  () => vi.fn(() => ({ username: 'testuser' }))
);
const mockHomedir = vi.hoisted(() => vi.fn(() => '/home/testuser'));

vi.mock('keytar', () => ({
  default: null,
  setPassword: vi.fn(),
  getPassword: vi.fn(),
  deletePassword: vi.fn(),
}));

vi.mock('http', () => ({
  createServer: mockCreateServer,
}));

vi.mock('https', () => ({
  request: mockHttpsRequest,
}));

vi.mock('child_process', () => ({
  execFile: mockExecFile,
}));

vi.mock('fs', () => ({
  existsSync: mockExistsSync,
  mkdirSync: mockMkdirSync,
  writeFileSync: mockWriteFileSync,
  readFileSync: mockReadFileSync,
  chmodSync: mockChmodSync,
  unlinkSync: mockUnlinkSync,
}));

vi.mock('os', () => ({
  hostname: mockHostname,
  userInfo: mockUserInfo,
  homedir: mockHomedir,
}));

import {
  generatePKCE,
  startLocalhostServer,
  encryptData,
  decryptData,
  openBrowser,
  storeTokenInKeychain,
  getTokenFromKeychain,
  removeTokenFromKeychain,
} from './oauth';

beforeEach(() => {
  vi.clearAllMocks();
  mockExistsSync.mockReturnValue(false);
  mockHostname.mockReturnValue('test-machine');
  mockUserInfo.mockReturnValue({ username: 'testuser' });
  mockHomedir.mockReturnValue('/home/testuser');
});

// ─── generatePKCE ────────────────────────────────────────────────

describe('generatePKCE', () => {
  it('returns verifier and challenge as strings', () => {
    const result = generatePKCE();
    expect(typeof result.verifier).toBe('string');
    expect(typeof result.challenge).toBe('string');
    expect(result.verifier.length).toBeGreaterThan(32);
    expect(result.challenge.length).toBeGreaterThan(32);
  });

  it('generates a valid base64url verifier (no padding, no +/ )', () => {
    const result = generatePKCE();
    expect(result.verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('challenge is the SHA-256 hash of verifier in base64url', () => {
    const result = generatePKCE();
    const hash = crypto.createHash('sha256').update(result.verifier).digest();
    const expectedChallenge = hash
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(result.challenge).toBe(expectedChallenge);
  });

  it('generates unique values on each call', () => {
    const a = generatePKCE();
    const b = generatePKCE();
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.challenge).not.toBe(b.challenge);
  });
});

// ─── encryptData / decryptData ───────────────────────────────────

describe('encryptData / decryptData', () => {
  it('round-trips data correctly', () => {
    const key = 'test-key-123';
    const data = JSON.stringify({
      token: 'gho_abc123',
      refresh: 'rty_def456',
    });
    const encrypted = encryptData(data, key);
    expect(typeof encrypted).toBe('string');
    expect(encrypted).toMatch(/^[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/);

    const decrypted = decryptData(encrypted, key);
    expect(decrypted).toBe(data);
  });

  it('round-trips empty string', () => {
    const encrypted = encryptData('', 'key');
    const decrypted = decryptData(encrypted, 'key');
    expect(decrypted).toBe('');
  });

  it('returns null when decrypting with wrong key', () => {
    const encrypted = encryptData('secret-data', 'correct-key');
    const result = decryptData(encrypted, 'wrong-key');
    expect(result).toBeNull();
  });

  it('returns null for invalid encrypted format', () => {
    expect(decryptData('not-enough-parts', 'key')).toBeNull();
    expect(decryptData('a:b', 'key')).toBeNull();
    expect(decryptData('a:b:c:d', 'key')).toBeNull();
  });

  it('returns null for garbage input', () => {
    expect(decryptData('!!!!:!!!!:!!!!', 'key')).toBeNull();
  });

  it('produces different ciphertexts for same input (different IV)', () => {
    const a = encryptData('same-data', 'same-key');
    const b = encryptData('same-data', 'same-key');
    expect(a).not.toBe(b);
  });
});

// ─── startLocalhostServer ────────────────────────────────────────

describe('startLocalhostServer', () => {
  let capturedHandler: Function;
  let mockServer: any;
  let clock: any;

  beforeEach(() => {
    mockServer = {
      listen: vi.fn(),
      close: vi.fn(),
      unref: vi.fn(),
    };
    mockCreateServer.mockImplementation((handler: Function) => {
      capturedHandler = handler;
      return mockServer;
    });
    clock = vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates an HTTP server on 127.0.0.1 at the given port', () => {
    startLocalhostServer(8742, 'callback');
    expect(mockCreateServer).toHaveBeenCalledTimes(1);
    expect(mockServer.listen).toHaveBeenCalledWith(8742, '127.0.0.1');
  });

  it('resolves with code and state from the callback URL', async () => {
    const promise = startLocalhostServer(8742, 'callback');

    const mockReq = { url: '/callback?code=auth123&state=xyz789' };
    const mockRes = { writeHead: vi.fn(), end: vi.fn() };

    expect(typeof capturedHandler).toBe('function');
    capturedHandler(mockReq, mockRes);

    const result = await promise;
    expect(result).toEqual({ code: 'auth123', state: 'xyz789' });
    expect(mockServer.close).toHaveBeenCalled();
    expect(mockRes.writeHead).toHaveBeenCalledWith(200, {
      'Content-Type': 'text/html',
    });
  });

  it('uses default redirect path "callback" when none given', () => {
    startLocalhostServer(8742);
    const mockReq = { url: '/callback?code=c&state=s' };
    const mockRes = { writeHead: vi.fn(), end: vi.fn() };
    capturedHandler(mockReq, mockRes);
    expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
  });

  it('rejects when callback is missing code or state', async () => {
    const promise = startLocalhostServer(8742, 'callback');
    const mockReq = { url: '/callback?error=access_denied' };
    const mockRes = { writeHead: vi.fn(), end: vi.fn() };

    capturedHandler(mockReq, mockRes);

    await expect(promise).rejects.toThrow('Missing code or state in callback');
    expect(mockRes.writeHead).toHaveBeenCalledWith(400, {
      'Content-Type': 'text/html',
    });
    expect(mockServer.close).toHaveBeenCalled();
  });

  it('rejects with timeout error if no callback received within 5 minutes', async () => {
    const promise = startLocalhostServer(8742, 'callback');

    clock.advanceTimersByTime(5 * 60 * 1000 + 100);

    await expect(promise).rejects.toThrow('OAuth callback timeout');
    expect(mockServer.close).toHaveBeenCalled();
  });

  it('returns 404 for paths other than the callback path', () => {
    startLocalhostServer(8742, 'callback');
    const mockReq = { url: '/other' };
    const mockRes = { writeHead: vi.fn(), end: vi.fn() };
    capturedHandler(mockReq, mockRes);
    expect(mockRes.writeHead).toHaveBeenCalledWith(404, {
      'Content-Type': 'text/plain',
    });
  });
});

// ─── openBrowser ─────────────────────────────────────────────────

describe('openBrowser', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('calls "open" on macOS', async () => {
    vi.stubGlobal('process', { ...process, platform: 'darwin' });
    const promise = openBrowser('https://example.com/auth');
    expect(mockExecFile).toHaveBeenCalledWith(
      'open',
      ['https://example.com/auth'],
      expect.any(Function)
    );
    const cb = mockExecFile.mock.calls[0][2];
    cb(null);
    await promise;
  });

  it('calls "xdg-open" on Linux', async () => {
    vi.stubGlobal('process', { ...process, platform: 'linux' });
    const promise = openBrowser('https://example.com/auth');
    expect(mockExecFile).toHaveBeenCalledWith(
      'xdg-open',
      ['https://example.com/auth'],
      expect.any(Function)
    );
    const cb = mockExecFile.mock.calls[0][2];
    cb(null);
    await promise;
  });

  it('calls "cmd /c start" on Windows', async () => {
    vi.stubGlobal('process', { ...process, platform: 'win32' });
    const promise = openBrowser('https://example.com/auth');
    expect(mockExecFile).toHaveBeenCalledWith(
      'cmd',
      ['/c', 'start', '""', 'https://example.com/auth'],
      expect.any(Function)
    );
    const cb = mockExecFile.mock.calls[0][2];
    cb(null);
    await promise;
  });

  it('rejects when execFile errors', async () => {
    vi.stubGlobal('process', { ...process, platform: 'darwin' });
    const promise = openBrowser('https://example.com/auth');
    const cb = mockExecFile.mock.calls[0][2];
    cb(new Error('ENOENT'));
    await expect(promise).rejects.toThrow('ENOENT');
  });
});

// ─── storeTokenInKeychain fallback ───────────────────────────────

describe('storeTokenInKeychain (fallback to encrypted file)', () => {
  beforeEach(() => {
    mockExistsSync.mockReturnValue(false);
  });

  it('stores and retrieves a token via encrypted file fallback', async () => {
    const stored = await storeTokenInKeychain(
      'sentinel-oracle',
      'gemini',
      'test-access-token'
    );
    expect(stored).toBe(true);

    // Should have called mkdirSync for sentinel dir and writeFileSync
    expect(mockMkdirSync).toHaveBeenCalled();
    expect(mockWriteFileSync).toHaveBeenCalled();

    const encryptedContent = mockWriteFileSync.mock.calls[0][1];
    expect(typeof encryptedContent).toBe('string');
    expect(encryptedContent).toMatch(/^[^:]+:[^:]+:[^:]+$/);

    // Now mock read to return what was written
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(encryptedContent);

    const retrieved = await getTokenFromKeychain('sentinel-oracle', 'gemini');
    expect(retrieved).toBe('test-access-token');
  });

  it('returns null for unknown account', async () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(
      encryptData(
        JSON.stringify({ 'sentinel-oracle:gemini': 'stored-token' }),
        'test-machine-testuser-sentinel-oracle'
      )
    );

    const result = await getTokenFromKeychain('sentinel-oracle', 'claude');
    expect(result).toBeNull();
  });

  it('removes a stored token and cleans up file when empty', async () => {
    // First store one token
    await storeTokenInKeychain('sentinel-oracle', 'gemini', 'token-1');
    const encryptedContent = mockWriteFileSync.mock.calls[0][1];

    // Now remove it
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(encryptedContent);

    const removed = await removeTokenFromKeychain('sentinel-oracle', 'gemini');
    expect(removed).toBe(true);

    // File should be deleted since it's now empty
    expect(mockUnlinkSync).toHaveBeenCalled();
  });

  it('does not error when removing non-existent credential', async () => {
    mockExistsSync.mockReturnValue(true);
    mockReadFileSync.mockReturnValue(
      encryptData(JSON.stringify({}), 'test-machine-testuser-sentinel-oracle')
    );

    const result = await removeTokenFromKeychain(
      'sentinel-oracle',
      'nonexistent'
    );
    expect(result).toBe(true);
  });

  it('returns null from getTokenFromKeychain when credentials file is missing', async () => {
    mockExistsSync.mockReturnValue(false);
    const result = await getTokenFromKeychain('sentinel-oracle', 'gemini');
    expect(result).toBeNull();
  });
});
