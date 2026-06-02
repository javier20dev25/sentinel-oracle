import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LiteScanner } from './lite_scanner.js';
import { SignalVault } from '../../cli/intelligence/signal_vault.js';

vi.mock('../../cli/intelligence/signal_vault', () => {
  const mockVault = {
    recordSignal: vi.fn(),
    recordScan: vi.fn(),
    getCorrelations: vi.fn().mockReturnValue([]),
    getHistoricalSignals: vi.fn().mockReturnValue([]),
  };
  return { SignalVault: vi.fn(function () { return mockVault; }) };
});

describe('LiteScanner', () => {
  let scanner: LiteScanner;

  beforeEach(() => {
    vi.clearAllMocks();
    scanner = new LiteScanner();
  });

  describe('scanPatch', () => {
    describe('filename-based detection', () => {
      it('detects .env files', () => {
        const findings = scanner.scanPatch('.env', '');
        expect(findings).toHaveLength(1);
        expect(findings[0]).toMatchObject({ type: 'SECRET_ENV_FILE', severity: 'HIGH', intent: 'EXFILTRATION' });
      });

      it('detects .env.production files', () => {
        const findings = scanner.scanPatch('.env.production', '');
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe('SECRET_ENV_FILE');
      });

      it('detects .env.example files', () => {
        const findings = scanner.scanPatch('.env.example', '');
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe('SECRET_ENV_FILE');
      });

      it('detects credentials.json files', () => {
        const findings = scanner.scanPatch('credentials.json', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects credentials.yml files', () => {
        const findings = scanner.scanPatch('config/credentials.yml', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects secrets.json files', () => {
        const findings = scanner.scanPatch('secrets.json', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects secrets.yml files', () => {
        const findings = scanner.scanPatch('secrets.yml', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects key.json files', () => {
        const findings = scanner.scanPatch('key.json', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects service-account.json files', () => {
        const findings = scanner.scanPatch('service-account.json', '');
        expect(findings[0].type).toBe('SECRET_CREDENTIALS_FILE');
      });

      it('detects id_rsa files', () => {
        const findings = scanner.scanPatch('id_rsa', '');
        expect(findings[0].type).toBe('SECRET_SSH_KEY_FILE');
      });

      it('detects id_ed25519 files', () => {
        const findings = scanner.scanPatch('id_ed25519', '');
        expect(findings[0].type).toBe('SECRET_SSH_KEY_FILE');
      });

      it('detects id_ecdsa files', () => {
        const findings = scanner.scanPatch('path/to/id_ecdsa', '');
        expect(findings[0].type).toBe('SECRET_SSH_KEY_FILE');
      });

      it('detects id_dsa files', () => {
        const findings = scanner.scanPatch('id_dsa', '');
        expect(findings[0].type).toBe('SECRET_SSH_KEY_FILE');
      });

      it('returns no filename findings for normal files', () => {
        const findings = scanner.scanPatch('index.ts', '');
        expect(findings).toHaveLength(0);
      });
    });

    describe('SAST rule detection', () => {
      it('detects UNSAFE_EVAL', () => {
        const patch = `+  eval(userInput);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'UNSAFE_EVAL')).toBe(true);
      });

      it('detects new Function', () => {
        const patch = `+  new Function("return " + data);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'UNSAFE_EVAL')).toBe(true);
      });

      it('detects OS_CAPABILITY via require(child_process)', () => {
        const patch = `+  require('child_process');\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'OS_CAPABILITY')).toBe(true);
      });

      it('detects OS_CAPABILITY via spawn', () => {
        const patch = `+  spawn('ls', ['-la']);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'OS_CAPABILITY')).toBe(true);
      });

      it('detects NETWORK_ACTIVITY via fetch', () => {
        const patch = `+  fetch('https://evil.com');\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'NETWORK_ACTIVITY')).toBe(true);
      });

      it('detects NETWORK_ACTIVITY via axios', () => {
        const patch = `+  axios.post(url, data);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'NETWORK_ACTIVITY')).toBe(true);
      });

      it('detects ENV_ACCESS via process.env', () => {
        const patch = `+  const key = process.env.SECRET_TOKEN;\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'ENV_ACCESS')).toBe(true);
      });

      it('detects POTENTIAL_SECRET via Buffer.from base64', () => {
        const patch = `+  const decoded = Buffer.from(encoded, 'base64');\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'POTENTIAL_SECRET')).toBe(true);
      });

      it('detects DOM_INJECTION via innerHTML', () => {
        const patch = `+  element.innerHTML = userInput;\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'DOM_INJECTION')).toBe(true);
      });

      it('detects SANDBOX_ESCAPE via vm.runInContext', () => {
        const patch = `+  vm.runInContext(code, ctx);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.some(f => f.type === 'SANDBOX_ESCAPE')).toBe(true);
      });

      it('detects SECRET_AWS_KEY_ID', () => {
        const patch = `+  AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_AWS_KEY_ID')).toBe(true);
      });

      it('detects bare AKIA pattern', () => {
        const patch = `+  const key = AKIAIOSFODNN7EXAMPLE;\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_AWS_KEY_ID')).toBe(true);
      });

      it('detects SECRET_AWS_SECRET', () => {
        const patch = `+  AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_AWS_SECRET')).toBe(true);
      });

      it('detects SECRET_GITHUB_TOKEN (gh pattern)', () => {
        const token = ['g', 'hp', '_'].join('') + 'a'.repeat(36);
        const patch = `+  const token = '${token}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_GITHUB_TOKEN')).toBe(true);
      });

      it('detects SECRET_GITHUB_TOKEN (github_pat pattern)', () => {
        const token = ['g', 'ithub_p', 'at_'].join('') + 'a'.repeat(28);
        const patch = `+  const pat = '${token}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_GITHUB_TOKEN')).toBe(true);
      });

      it('detects SECRET_STRIPE_KEY', () => {
        const stripe = ['s', 'k', '_l', 'ive', '_'].join('');
        const patch = `+  stripe_key = '${stripe}${'x'.repeat(24)}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_STRIPE_KEY')).toBe(true);
      });

      it('detects SECRET_SENDGRID_KEY', () => {
        const sg = ['S', 'G.'].join('') + 'a'.repeat(40);
        const patch = `+  sendgrid = '${sg}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_SENDGRID_KEY')).toBe(true);
      });

      it('detects SECRET_SSH_KEY', () => {
        const pem = ['-----BEG', 'IN RSA ', 'PRIVATE', ' KEY-----'].join('');
        const patch = `+  ${pem}\n`;
        const findings = scanner.scanPatch('key.pem', patch);
        expect(findings.some(f => f.type === 'SECRET_SSH_KEY')).toBe(true);
      });

      it('detects SECRET_SLACK_TOKEN', () => {
        const token = ['xo', 'xb-', 'a'.repeat(20)].join('');
        const patch = `+  const token = '${token}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_SLACK_TOKEN')).toBe(true);
      });

      it('detects SECRET_SLACK_WEBHOOK', () => {
        const hook = ['https://hoo', 'ks.slack', '.com/serv', 'ices/T00XX', 'XXXX/B00XX', 'XXXX/'].join('') + 'x'.repeat(26);
        const patch = `+  const url = '${hook}';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_SLACK_WEBHOOK')).toBe(true);
      });

      it('detects SECRET_JWT', () => {
        const patch = `+  JWT_SECRET = 'abcdefghijklmnopqrstuvwxyz0123456789';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_JWT')).toBe(true);
      });

      it('detects SECRET_DB_PASSWORD', () => {
        const patch = `+  DB_PASSWORD = 'supersecret123!';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_DB_PASSWORD')).toBe(true);
      });

      it('detects SECRET_ENCRYPTION_KEY', () => {
        const patch = `+  ENCRYPTION_KEY = 'my-encryption-key-here!';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_ENCRYPTION_KEY')).toBe(true);
      });

      it('detects SECRET_API_KEY', () => {
        const patch = `+  API_KEY = 'abcdefghijklmnopqrstuvwxyz012345';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_API_KEY')).toBe(true);
      });

      it('detects DARKNET_ADDRESS', () => {
        const patch = `+  const url = 'http://darknetmarket.onion';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'DARKNET_ADDRESS')).toBe(true);
      });

      it('detects SECRET_HARDCODED_PASSWORD', () => {
        const patch = `+  password = 'correct-horse-battery-staple';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_HARDCODED_PASSWORD')).toBe(true);
      });

      it('detects SECRET_HARDCODED_TOKEN', () => {
        const patch = `+  token = 'abcdefghijklmnopqrstuvwxyz012345';\n`;
        const findings = scanner.scanPatch('config.js', patch);
        expect(findings.some(f => f.type === 'SECRET_HARDCODED_TOKEN')).toBe(true);
      });

      it('detects multiple findings on one line', () => {
        const patch = `+  fetch(url); eval(code);\n`;
        const findings = scanner.scanPatch('test.js', patch);
        const types = findings.map(f => f.type);
        expect(types).toContain('NETWORK_ACTIVITY');
        expect(types).toContain('UNSAFE_EVAL');
      });
    });

    describe('diff format parsing', () => {
      it('parses chunk headers correctly for line numbers', () => {
        const patch = [
          '@@ -1,3 +10,7 @@',
          '+ eval(evil);',
          ' unchanged',
          '- removed',
          '+ spawn("ls");',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(2);
        expect(findings[0].line).toBe(10);
        expect(findings[1].line).toBe(12);
      });

      it('ignores --- lines (removed lines)', () => {
        const patch = [
          '+ valid line',
          '- eval(danger);',
          '+ another valid',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings.every(f => f.line !== 2)).toBe(true);
      });

      it('handles multiple chunk headers', () => {
        const patch = [
          '@@ -5,3 +15,7 @@',
          '+ eval(first);',
          ' context',
          '@@ -20,6 +30,8 @@',
          '+ eval(second);',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(2);
        expect(findings[0].line).toBe(15);
        expect(findings[1].line).toBe(30);
      });

      it("ignores '+++' lines (file rename headers)", () => {
        const patch = [
          '+++ b/newfile.js',
          '+ eval(test);',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(1);
        expect(findings[0].line).toBe(2);
      });
    });

    describe('safe code', () => {
      it('returns no findings for benign code', () => {
        const patch = [
          '+ const x = 42;',
          '+ console.log("hello");',
          '+ const y = x + 1;',
          '+ function add(a, b) { return a + b; }',
          '+ export default add;',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(0);
      });

      it('returns no findings for empty patch', () => {
        const findings = scanner.scanPatch('test.js', '');
        expect(findings).toHaveLength(0);
      });
    });

    describe('edge cases', () => {
      it('returns no findings for patch with only context lines', () => {
        const patch = [
          '  const x = 1;',
          '  const y = 2;',
          '  eval(x + y);',
        ].join('\n');
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(0);
      });

      it('handles binary-like content without crashing', () => {
        const patch = '+ \x00\x01\x02\x03\x04\xff\xfe\xfd\xfc';
        const findings = scanner.scanPatch('binary.bin', patch);
        expect(Array.isArray(findings)).toBe(true);
      });

      it('handles very long lines without crashing', () => {
        const longLine = '+ ' + 'a'.repeat(5000);
        const findings = scanner.scanPatch('test.js', longLine);
        expect(Array.isArray(findings)).toBe(true);
      });

      it('handles empty added lines', () => {
        const patch = '+\n+  \n+  eval(x);\n';
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(1);
      });

      it('handles unicode content', () => {
        const patch = '+ const ñ = "eval sería malo aquí";\n';
        const findings = scanner.scanPatch('test.js', patch);
        expect(findings).toHaveLength(0);
      });
    });
  });

  describe('auditPR', () => {
    it('returns a verdict with scanId and findings', async () => {
      const result = await scanner.auditPR('test-repo', 42, 'test-author', [
        { filename: 'test.js', patch: '+  eval(x);\n' },
      ]);
      expect(result.scanId).toBeDefined();
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].type).toBe('UNSAFE_EVAL');
      expect(result.verdict).toBeDefined();
      expect(result.verdict.band).toBe('CRITICAL');
      expect(result.verdict.decision).toBe('BLOCK');
      expect(result.cta).toBe('View advanced causal audit on Sentinel Cloud');
    });

    it('returns PASS verdict when no critical or high findings', async () => {
      const result = await scanner.auditPR('test-repo', 42, 'test-author', [
        { filename: 'test.js', patch: '+  const x = 1;\n' },
      ]);
      expect(result.verdict.decision).toBe('PASS');
      expect(result.verdict.band).toBe('SAFE');
      expect(result.cta).toBeNull();
    });

    it('returns REVIEW for high severity findings', async () => {
      const result = await scanner.auditPR('test-repo', 42, 'test-author', [
        { filename: 'test.js', patch: '+  element.innerHTML = x;\n' },
      ]);
      expect(result.verdict.decision).toBe('REVIEW');
      expect(result.verdict.band).toBe('SUSPICIOUS');
    });

    it('records signals in the vault', async () => {
      await scanner.auditPR('test-repo', 42, 'test-author', [
        { filename: 'test.js', patch: '+  eval(x);\n' },
      ]);
      expect(SignalVault).toHaveBeenCalledTimes(1);
    });
  });
});
