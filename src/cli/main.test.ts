import { describe, it, expect, vi, beforeAll } from 'vitest';

const mockIntegrityCheck = vi.hoisted(() => vi.fn().mockResolvedValue({ level: 'TRUSTED', reasons: [] }));
const mockReport = vi.hoisted(() => vi.fn());
const mockRunDoctor = vi.hoisted(() => vi.fn());
const mockScanPatch = vi.hoisted(() => vi.fn(() => []));
const mockOracleInteractive = vi.hoisted(() => vi.fn());
const mockOracleAsk = vi.hoisted(() => vi.fn());
const mockSetApiKey = vi.hoisted(() => vi.fn());
const mockRemoveApiKey = vi.hoisted(() => vi.fn());
const mockListProviders = vi.hoisted(() => vi.fn(() => []));
const mockSetConfig = vi.hoisted(() => vi.fn());

vi.mock('../core/lite/lite_scanner', () => ({
  LiteScanner: class {
    scanPatch = mockScanPatch;
  },
  LiteFinding: class {},
}));

vi.mock('../oracle/command', () => ({
  oracleInteractive: mockOracleInteractive,
  oracleAsk: mockOracleAsk,
}));

vi.mock('../oracle/auth', () => ({
  setApiKey: mockSetApiKey,
  removeApiKey: mockRemoveApiKey,
  listProviders: mockListProviders,
  setConfig: mockSetConfig,
}));

vi.mock('./intelligence/integrity_manager', () => ({
  IntegrityManager: class {
    checkIntegrity = mockIntegrityCheck;
    report = mockReport;
  },
}));

vi.mock('./intelligence/system_auditor', () => ({
  SystemAuditor: class {
    runDoctor = mockRunDoctor;
  },
}));

describe('CLI commander setup', () => {
  beforeAll(async () => {
    process.argv = ['node', 'main.js', '--help'];
  });

  it('should load main module without commander duplicate error', async () => {
    let mod: any;
    let err: Error | null = null;
    const origExit = process.exit;
    const origLog = console.log;
    process.exit = vi.fn() as any;
    console.log = vi.fn();
    try {
      mod = await import('./main');
    } catch (e) {
      err = e as Error;
    } finally {
      process.exit = origExit;
      console.log = origLog;
    }
    expect(err).toBeNull();
    expect(mod).toBeDefined();
  });

  it('should not throw for each command registration', async () => {
    const { Command } = await import('commander');
    const program = new Command();

    expect(() => {
      const p = program.command('test');
      const auth = p.command('auth');
      auth.command('set');
      auth.command('remove');
      auth.command('list');
      p.command('ask');
      p.command('set-model');
      p.command('interactive').alias('chat');
    }).not.toThrow();
  });
});
