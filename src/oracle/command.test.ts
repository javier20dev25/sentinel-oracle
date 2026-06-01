import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Message, ToolDef, BaseProvider } from './providers/base';

// ─── Hoisted mocks ────────────────────────────────────────────

const mockOracleChat = vi.hoisted(() => vi.fn());
const mockGetDefaultProvider = vi.hoisted(() => vi.fn());
const mockOracleChatStream = vi.hoisted(() => vi.fn());
const mockSetApiKey = vi.hoisted(() => vi.fn());
const mockRemoveApiKey = vi.hoisted(() => vi.fn());
const mockListProviders = vi.hoisted(() => vi.fn());
const mockSetConfig = vi.hoisted(() => vi.fn());
const mockGetConfig = vi.hoisted(() => vi.fn());
const mockGetToolDefs = vi.hoisted(() => vi.fn());
const mockCreateProvider = vi.hoisted(() => vi.fn());
const mockAddRule = vi.hoisted(() => vi.fn());
const mockRemoveRule = vi.hoisted(() => vi.fn());
const mockToggleRule = vi.hoisted(() => vi.fn());
const mockListRules = vi.hoisted(() => vi.fn(() => []));
const mockGetDefaultRules = vi.hoisted(() => vi.fn(() => []));
const mockEnsureDefaultRules = vi.hoisted(() => vi.fn());
const mockAddThreat = vi.hoisted(() => vi.fn());
const mockGetThreatsByAuthor = vi.hoisted(() => vi.fn(() => []));
const mockGetRecentThreats = vi.hoisted(() => vi.fn(() => []));
const mockGetHighRiskAuthors = vi.hoisted(() => vi.fn(() => []));
const mockGetThreatAuthor = vi.hoisted(() => vi.fn());
const mockCorrelateFindings = vi.hoisted(() => vi.fn(() => ({
  knownAuthor: false, authorThreats: [], patternMatches: [],
  authorRiskLevel: 'unknown', threatCount: 0,
})));
const mockCloseDb = vi.hoisted(() => vi.fn());
const mockWelcomeBanner = vi.hoisted(() => vi.fn(() => ''));
const mockSummaryBox = vi.hoisted(() => vi.fn(() => ''));
const mockToolCard = vi.hoisted(() => vi.fn(() => '[TOOLCARD]'));
const mockInsight = vi.hoisted(() => vi.fn(() => ''));
const mockSevColor = vi.hoisted(() => vi.fn((s: string) => s));
const mockSevColorFn = vi.hoisted(() => vi.fn(() => (s: string) => s));
const mockAttackChain = vi.hoisted(() => vi.fn(() => ''));
const mockCapabilityBars = vi.hoisted(() => vi.fn(() => ''));
const mockSeverityPie = vi.hoisted(() => vi.fn(() => ''));
const mockFileHeatmap = vi.hoisted(() => vi.fn(() => ''));
const mockPermissionBannerText = vi.hoisted(() => vi.fn(() => ''));
const mockModeBanner = vi.hoisted(() => vi.fn((m: string) => `[MODE: ${m}]`));
const mockFindingsBox = vi.hoisted(() => vi.fn(() => ''));
const mockGenerateMarkdown = vi.hoisted(() => vi.fn(() => '# Markdown'));
const mockGenerateJSON = vi.hoisted(() => vi.fn(() => '{}'));
const mockSaveReport = vi.hoisted(() => vi.fn(() => '/tmp/report.md'));
const mockParseFindingsFromOutput = vi.hoisted(() => vi.fn(() => []));
const mockSpinner = vi.hoisted(() => {
  return function() {
    this.start = vi.fn();
    this.stop = vi.fn();
    this.update = vi.fn();
  };
});
const mockSetTone = vi.hoisted(() => vi.fn());
const mockGetCurrentTone = vi.hoisted(() => vi.fn(() => ({
  id: 'neutral', label: 'Neutral', description: 'Balanced', systemInstruction: '',
})));
const mockSelectToneModal = vi.hoisted(() => vi.fn());
const mockTONES = vi.hoisted(() => []);
const mockSetAgent = vi.hoisted(() => vi.fn());
const mockGetCurrentAgent = vi.hoisted(() => vi.fn(() => ({
  id: 'default', name: 'Default', icon: '[*]', description: '', systemPromptAddendum: '',
})));
const mockAGENTS = vi.hoisted(() => [
  { id: 'default', name: 'Default', icon: '[*]', description: 'Default agent', systemPromptAddendum: '' },
  { id: 'blue', name: 'Blue Team', icon: '[B]', description: 'Defensive', systemPromptAddendum: '' },
]);
const mockDetectCli1 = vi.hoisted(() => vi.fn(() => ({
  found: false, configPath: '', dataDir: '', config: {}, classifiedCount: 0, vaultDbPath: '',
})));
const mockFormatCli1Report = vi.hoisted(() => vi.fn(() => 'No CLI 1 found.'));
const mockImportCli1Classified = vi.hoisted(() => vi.fn(() => ({ imported: 0, files: [] })));
const mockExecFileSync = vi.hoisted(() => vi.fn());
const mockRunGuard = vi.hoisted(() => vi.fn(() => ({
  passed: true, machine: { status: 'OK', detail: '' },
  gh: { status: 'OK', detail: '' }, auth: { status: 'OK', detail: '' },
  remote: { status: 'OK', detail: '' }, repo: { status: 'OK', detail: '' },
})));
const mockFormatGuardReport = vi.hoisted(() => vi.fn(() => 'Guard passed.'));

// ─── vi.mock calls ────────────────────────────────────────────

vi.mock('./engine', () => ({
  oracleChat: mockOracleChat,
  getDefaultProvider: mockGetDefaultProvider,
  oracleChatStream: mockOracleChatStream,
  ToolPermissionCallback: null as any,
  OracleMode: {} as any,
}));

vi.mock('./auth', () => ({
  setApiKey: mockSetApiKey,
  removeApiKey: mockRemoveApiKey,
  listProviders: mockListProviders,
  setConfig: mockSetConfig,
  getConfig: mockGetConfig,
}));

vi.mock('./tools', () => ({
  getToolDefs: mockGetToolDefs,
}));

vi.mock('./providers', () => ({
  createProvider: mockCreateProvider,
  ProviderName: {} as any,
}));

vi.mock('./rules', () => ({
  addRule: mockAddRule,
  removeRule: mockRemoveRule,
  toggleRule: mockToggleRule,
  listRules: mockListRules,
  getDefaultRules: mockGetDefaultRules,
  ensureDefaultRules: mockEnsureDefaultRules,
}));

vi.mock('./threat_db', () => ({
  addThreat: mockAddThreat,
  getThreatsByAuthor: mockGetThreatsByAuthor,
  getRecentThreats: mockGetRecentThreats,
  getHighRiskAuthors: mockGetHighRiskAuthors,
  getThreatAuthor: mockGetThreatAuthor,
  correlateFindings: mockCorrelateFindings,
  closeDb: mockCloseDb,
}));

vi.mock('./viz', () => ({
  welcomeBanner: mockWelcomeBanner,
  summaryBox: mockSummaryBox,
  toolCard: mockToolCard,
  insight: mockInsight,
  sevColor: mockSevColor,
  sevColorFn: mockSevColorFn,
  attackChain: mockAttackChain,
  capabilityBars: mockCapabilityBars,
  severityPie: mockSeverityPie,
  fileHeatmap: mockFileHeatmap,
  permissionBannerText: mockPermissionBannerText,
  modeBanner: mockModeBanner,
  findingsBox: mockFindingsBox,
}));

vi.mock('./reports', () => ({
  generateMarkdown: mockGenerateMarkdown,
  generateJSON: mockGenerateJSON,
  saveReport: mockSaveReport,
  ReportData: {} as any,
  ReportFinding: {} as any,
  parseFindingsFromOutput: mockParseFindingsFromOutput,
}));

vi.mock('./spinner', () => ({
  Spinner: mockSpinner,
}));

vi.mock('./tono', () => ({
  setTone: mockSetTone,
  getCurrentTone: mockGetCurrentTone,
  TONES: mockTONES,
  selectToneModal: mockSelectToneModal,
}));

vi.mock('./agents', () => ({
  setAgent: mockSetAgent,
  getCurrentAgent: mockGetCurrentAgent,
  AGENTS: mockAGENTS,
}));

vi.mock('./cli1_bridge', () => ({
  detectCli1: mockDetectCli1,
  formatCli1Report: mockFormatCli1Report,
  importCli1Classified: mockImportCli1Classified,
}));

vi.mock('./gh_guard', () => ({
  runGuard: mockRunGuard,
  formatGuardReport: mockFormatGuardReport,
}));

vi.mock('child_process', () => ({
  execFileSync: mockExecFileSync,
}));

import {
  handleSlash,
  SLASH_COMMANDS,
  conversationHistory,
  currentMode,
  permissionCache,
} from './command';

beforeEach(() => {
  vi.clearAllMocks();
  conversationHistory.length = 0;
  // Reset currentMode via assignment
  const resetMode = async () => {
    // Reassign via handleSlash('/mode execute')
    await handleSlash('/mode execute');
  };
  void resetMode();
  permissionCache.clear();
  mockListProviders.mockReturnValue([]);
  mockGetToolDefs.mockReturnValue([
    { name: 'scan', description: 'Scan files', parameters: { type: 'object', properties: {}, required: [] } },
  ]);
  mockGetConfig.mockReturnValue({});
  mockGetCurrentTone.mockReturnValue({
    id: 'neutral', label: 'Neutral', description: 'Balanced', systemInstruction: '',
  });
  mockGetCurrentAgent.mockReturnValue({
    id: 'default', name: 'Default', icon: '[*]', description: '', systemPromptAddendum: '',
  });
  mockListRules.mockReturnValue([]);
  mockGetRecentThreats.mockReturnValue([]);
  mockGetHighRiskAuthors.mockReturnValue([]);
  mockExecFileSync.mockReturnValue(Buffer.from('[]'));
});

// ─── SLASH_COMMANDS ───────────────────────────────────────────

describe('SLASH_COMMANDS', () => {
  const expectedCommands = [
    '/help', '/mode', '/mode plan', '/mode execute', '/mode auto',
    '/models', '/provider', '/tools', '/tools -v',
    '/guard', '/repos',
    '/history', '/clear', '/auth', '/trust', '/trust clear',
    '/report md', '/report json',
    '/rule list', '/rule add', '/rule remove', '/rule toggle',
    '/threat list', '/threat query', '/threat auth', '/threat correlate',
    '/tono', '/agent', '/agent list', '/agent set',
    '/findings', '/audit',
    '/cli1', '/cli1-import',
  ];

  for (const cmd of expectedCommands) {
    it(`includes ${cmd}`, () => {
      expect(SLASH_COMMANDS).toContain(cmd);
    });
  }

  it('contains all expected commands', () => {
    for (const cmd of expectedCommands) {
      expect(SLASH_COMMANDS).toContain(cmd);
    }
    expect(SLASH_COMMANDS.length).toBeGreaterThanOrEqual(expectedCommands.length);
  });
});

// ─── /help ────────────────────────────────────────────────────

describe('/help', () => {
  it('returns true and logs help text containing key sections', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/help');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalled();
    const logged = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logged).toContain('Sentinel Oracle Core');
    expect(logged).toContain('HOW TO USE');
    expect(logged).toContain('SLASH COMMANDS');
    expect(logged).toContain('COVER FORMAT');
    logSpy.mockRestore();
  });
});

// ─── /mode ────────────────────────────────────────────────────

describe('/mode', () => {
  it('shows current mode when no subcommand', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/mode');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[MODE: execute]'));
    logSpy.mockRestore();
  });

  it('switches to plan mode', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/mode plan');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[MODE: plan]'));
    logSpy.mockRestore();
  });

  it('switches to execute mode', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/mode execute');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[MODE: execute]'));
    logSpy.mockRestore();
  });

  it('switches to auto mode', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/mode auto');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[MODE: auto]'));
    logSpy.mockRestore();
  });
});

// ─── /history ─────────────────────────────────────────────────

describe('/history', () => {
  it('returns session statistics', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/history');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Session Statistics');
    expect(logs).toContain('Messages');
    expect(logs).toContain('Mode');
    logSpy.mockRestore();
  });
});

// ─── /clear ───────────────────────────────────────────────────

describe('/clear', () => {
  it('resets conversation history and permission cache', async () => {
    conversationHistory.push(
      { role: 'user', content: 'test' },
      { role: 'assistant', content: 'reply' },
    );
    permissionCache.add('scan:{}');

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/clear');
    expect(result).toBe(true);
    expect(conversationHistory).toHaveLength(0);
    expect(permissionCache.size).toBe(0);
    logSpy.mockRestore();
  });
});

// ─── /tools ───────────────────────────────────────────────────

describe('/tools', () => {
  it('lists available tools', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/tools');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Available Tools');
    expect(logs).toContain('scan');
    logSpy.mockRestore();
  });

  it('shows verbose descriptions with -v flag', async () => {
    mockGetToolDefs.mockReturnValue([
      { name: 'scan', description: 'Scan files for threats', parameters: { type: 'object', properties: { path: { type: 'string' } }, required: [] } },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/tools -v');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Scan files for threats');
    logSpy.mockRestore();
  });
});

// ─── /auth ────────────────────────────────────────────────────

describe('/auth', () => {
  it('shows auth status with no keys', async () => {
    mockListProviders.mockReturnValue([]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/auth');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Authentication Status');
    expect(logs).toContain('No API keys configured');
    logSpy.mockRestore();
  });

  it('shows configured keys', async () => {
    mockListProviders.mockReturnValue(['gemini', 'openai']);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/auth');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('gemini');
    expect(logs).toContain('openai');
    logSpy.mockRestore();
  });
});

// ─── /findings ────────────────────────────────────────────────

describe('/findings', () => {
  it('shows message when no tool output in session', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/findings');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('No tool output');
    logSpy.mockRestore();
  });

  it('shows last tool output when available', async () => {
    conversationHistory.push(
      { role: 'system', content: 'sys' },
      { role: 'user', content: 'scan' },
      { role: 'assistant', content: '' },
      { role: 'tool', content: 'CRITICAL secret found', tool_call_id: 'scan' },
    );
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/findings');
    expect(result).toBe(true);
    expect(logSpy).toHaveBeenCalled();
    logSpy.mockRestore();
  });
});

// ─── /audit ───────────────────────────────────────────────────

describe('/audit', () => {
  it('shows audit dashboard', async () => {
    mockListRules.mockReturnValue([
      { name: 'rule1', enabled: true, instruction: 'test', createdAt: '2025-01-01' },
    ]);
    mockGetRecentThreats.mockReturnValue([
      { id: 1, type: 'package', source: 'test', severity: 'HIGH', author: 'bob', detected_at: '2025-01-01' },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/audit');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Local Database Audit');
    expect(logs).toContain('Rules');
    expect(logs).toContain('Threats DB');
    logSpy.mockRestore();
  });
});

// ─── /rule ────────────────────────────────────────────────────

describe('/rule', () => {
  it('lists rules', async () => {
    mockListRules.mockReturnValue([
      { name: 'no-code', instruction: 'Never modify code', enabled: true, createdAt: '2025-01-01' },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule list');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('no-code');
    logSpy.mockRestore();
  });

  it('adds a rule', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule add my-rule Always check');
    expect(result).toBe(true);
    expect(mockAddRule).toHaveBeenCalledWith('my-rule', 'Always check');
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('my-rule');
    logSpy.mockRestore();
  });

  it('removes a rule', async () => {
    mockRemoveRule.mockReturnValue(true);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule remove my-rule');
    expect(result).toBe(true);
    expect(mockRemoveRule).toHaveBeenCalledWith('my-rule');
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('removed');
    logSpy.mockRestore();
  });

  it('shows not found when removing nonexistent rule', async () => {
    mockRemoveRule.mockReturnValue(false);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule remove missing');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('not found');
    logSpy.mockRestore();
  });

  it('toggles a rule', async () => {
    mockListRules.mockReturnValue([
      { name: 'my-rule', instruction: 'test', enabled: true, createdAt: '' },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule toggle my-rule');
    expect(result).toBe(true);
    expect(mockToggleRule).toHaveBeenCalled();
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('my-rule');
    logSpy.mockRestore();
  });

  it('shows usage when /rule add is missing args', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/rule add');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Usage');
    logSpy.mockRestore();
  });
});

// ─── /agent ───────────────────────────────────────────────────

describe('/agent', () => {
  it('shows current agent', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/agent');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Current Agent');
    expect(logs).toContain('Default');
    logSpy.mockRestore();
  });

  it('lists available agents', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/agent list');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Available Agents');
    expect(logs).toContain('Default');
    expect(logs).toContain('Blue Team');
    logSpy.mockRestore();
  });

  it('sets an agent', async () => {
    mockSetAgent.mockReturnValue(true);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/agent set blue');
    expect(result).toBe(true);
    expect(mockSetAgent).toHaveBeenCalledWith('blue');
    logSpy.mockRestore();
  });

  it('shows usage when /agent set has no id', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/agent set');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Usage');
    logSpy.mockRestore();
  });

  it('shows error for unknown agent', async () => {
    mockSetAgent.mockReturnValue(false);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/agent set unknown');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Unknown agent');
    logSpy.mockRestore();
  });
});

// ─── /threat ──────────────────────────────────────────────────

describe('/threat', () => {
  it('lists recent threats', async () => {
    mockGetRecentThreats.mockReturnValue([
      { id: 1, type: 'package', source: 'evil', severity: 'CRITICAL', author: 'attacker', detected_at: '2025-01-01', title: 'Malicious' },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/threat list');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Recent Threats');
    expect(logs).toContain('CRITICAL');
    logSpy.mockRestore();
  });

  it('shows empty message when no threats', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/threat list');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('No threats recorded');
    logSpy.mockRestore();
  });

  it('queries threat by author', async () => {
    mockGetThreatsByAuthor.mockReturnValue([
      { id: 1, type: 'pr', source: 'repo', severity: 'HIGH', detected_at: '2025-01-01' },
    ]);
    mockGetThreatAuthor.mockReturnValue({
      author: 'bob', risk_level: 'HIGH', first_seen: '2025-01-01',
      last_seen: '2025-01-02', threat_count: 3, patterns: '[]', repos: '[]',
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/threat query bob');
    expect(result).toBe(true);
    expect(mockGetThreatsByAuthor).toHaveBeenCalledWith('bob');
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Threat Intelligence');
    logSpy.mockRestore();
  });

  it('shows high-risk authors', async () => {
    mockGetHighRiskAuthors.mockReturnValue([
      { author: 'badactor', risk_level: 'CRITICAL', threat_count: 5, last_seen: '2025-01-01' },
    ]);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/threat auth');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('High-Risk Authors');
    expect(logs).toContain('badactor');
    logSpy.mockRestore();
  });

  it('correlates findings for an author', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/threat correlate bob');
    expect(result).toBe(true);
    expect(mockCorrelateFindings).toHaveBeenCalled();
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Correlation');
    logSpy.mockRestore();
  });
});

// ─── /cli1 ────────────────────────────────────────────────────

describe('/cli1', () => {
  it('shows CLI 1 bridge info', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/cli1');
    expect(result).toBe(true);
    expect(mockDetectCli1).toHaveBeenCalled();
    expect(mockFormatCli1Report).toHaveBeenCalled();
    logSpy.mockRestore();
  });

  it('imports CLI 1 classified files', async () => {
    mockImportCli1Classified.mockReturnValue({ imported: 3, files: ['a.md', 'b.md', 'c.md'] });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/cli1-import');
    expect(result).toBe(true);
    expect(mockImportCli1Classified).toHaveBeenCalled();
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Imported');
    logSpy.mockRestore();
  });

  it('shows message when no files to import', async () => {
    mockImportCli1Classified.mockReturnValue({ imported: 0, files: [] });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/cli1-import');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('No classified files');
    logSpy.mockRestore();
  });
});

// ─── /models ──────────────────────────────────────────────────

describe('/models', () => {
  it('lists available providers and models', async () => {
    mockListProviders.mockReturnValue(['gemini']);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/models');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Available Providers');
    expect(logs).toContain('gemini');
    expect(logs).toContain('claude');
    logSpy.mockRestore();
  });
});

// ─── /provider ────────────────────────────────────────────────

describe('/provider', () => {
  it('shows provider configuration', async () => {
    mockGetConfig.mockReturnValue({ provider: 'gemini', model: 'gemini-2.0-flash' });
    mockListProviders.mockReturnValue(['gemini']);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/provider');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Provider Configuration');
    expect(logs).toContain('gemini');
    logSpy.mockRestore();
  });

  it('shows none when no active provider', async () => {
    mockGetConfig.mockReturnValue({});
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/provider');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('none');
    logSpy.mockRestore();
  });
});

// ─── /guard ───────────────────────────────────────────────────

describe('/guard', () => {
  it('runs connection security guard', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/guard');
    expect(result).toBe(true);
    expect(mockRunGuard).toHaveBeenCalled();
    expect(mockFormatGuardReport).toHaveBeenCalled();
    logSpy.mockRestore();
  });
});

// ─── /trust ───────────────────────────────────────────────────

describe('/trust', () => {
  it('shows permission status', async () => {
    permissionCache.add('scan:{}');
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/trust');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Permission Status');
    expect(logs).toContain('1 tool(s)');
    logSpy.mockRestore();
  });

  it('clears permission cache', async () => {
    permissionCache.add('scan:{}');
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/trust clear');
    expect(result).toBe(true);
    expect(permissionCache.size).toBe(0);
    logSpy.mockRestore();
  });
});

// ─── /report ──────────────────────────────────────────────────

describe('/report', () => {
  it('generates markdown report', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/report md');
    expect(result).toBe(true);
    expect(mockGenerateMarkdown).toHaveBeenCalled();
    expect(mockSaveReport).toHaveBeenCalled();
    logSpy.mockRestore();
  });

  it('generates JSON report', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/report json');
    expect(result).toBe(true);
    expect(mockGenerateJSON).toHaveBeenCalled();
    logSpy.mockRestore();
  });
});

// ─── /tono ────────────────────────────────────────────────────

describe('/tono', () => {
  it('opens tone selector modal', async () => {
    mockSelectToneModal.mockResolvedValue('serio');
    mockGetCurrentTone.mockReturnValue({
      id: 'serio', label: 'Serio', description: 'Formal', systemInstruction: 'Be formal.',
    });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/tono');
    expect(result).toBe(true);
    expect(mockSelectToneModal).toHaveBeenCalled();
    logSpy.mockRestore();
  });

  it('handles cancelled tone selection', async () => {
    mockSelectToneModal.mockResolvedValue(null);
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/tono');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('cancelled');
    logSpy.mockRestore();
  });
});

// ─── /repos ───────────────────────────────────────────────────

describe('/repos', () => {
  it('fetches and displays repos', async () => {
    mockExecFileSync.mockReturnValue(Buffer.from(JSON.stringify([
      { name: 'my-repo', owner: { login: 'me' }, visibility: 'PUBLIC', description: 'My repo' },
    ])));
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/repos 5 me');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('my-repo');
    logSpy.mockRestore();
  });

  it('handles gh errors', async () => {
    mockExecFileSync.mockImplementation(() => { throw new Error('auth required'); });
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const result = await handleSlash('/repos');
    expect(result).toBe(true);
    const logs = logSpy.mock.calls.map(c => String(c[0])).join(' ');
    expect(logs).toContain('Error');
    logSpy.mockRestore();
  });
});

// ─── Unknown command ─────────────────────────────────────────

describe('unknown command', () => {
  it('returns false for unrecognized command', async () => {
    const result = await handleSlash('/nonexistent');
    expect(result).toBe(false);
  });

  it('handles command with spaces', async () => {
    const result = await handleSlash('/some unknown command');
    expect(result).toBe(false);
  });
});
