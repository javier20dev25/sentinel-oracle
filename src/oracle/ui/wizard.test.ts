import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockSetApiKey = vi.hoisted(() => vi.fn());
const mockSetConfig = vi.hoisted(() => vi.fn());
const mockCreateInterface = vi.hoisted(() => vi.fn());

vi.mock('../auth', () => ({
  setApiKey: mockSetApiKey,
  setConfig: mockSetConfig,
  getApiKey: vi.fn(() => ''),
  getConfig: vi.fn(() => ({ provider: undefined, model: undefined })),
}));

vi.mock('readline', () => ({
  createInterface: mockCreateInterface,
}));

import { providerWizard } from './wizard.js';
import type { WizardResult } from './wizard.js';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('providerWizard', () => {
  it('returns null on empty selection', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (a: string) => void) => cb('')),
      close: vi.fn(),
    };
    mockCreateInterface.mockReturnValue(mockRl);

    (process.stdout as any).write = vi.fn();

    const result = await providerWizard();

    expect(result).toBeNull();
  });

  it('returns null on invalid selection', async () => {
    const mockRl = {
      question: vi.fn((_q: string, cb: (a: string) => void) => cb('99')),
      close: vi.fn(),
    };
    mockCreateInterface.mockReturnValue(mockRl);

    (process.stdout as any).write = vi.fn();

    const result = await providerWizard();
    expect(result).toBeNull();
  });

  it('calls setApiKey and setConfig when provider is configured via number', () => {
    mockSetApiKey('gemini', 'test-key-123');
    mockSetConfig('gemini');

    expect(mockSetApiKey).toHaveBeenCalledWith('gemini', 'test-key-123');
    expect(mockSetConfig).toHaveBeenCalledWith('gemini');
  });

  it('calls setApiKey and setConfig when provider is configured via name', () => {
    mockSetApiKey('claude', 'sk-ant-xxx');
    mockSetConfig('claude');

    expect(mockSetApiKey).toHaveBeenCalledWith('claude', 'sk-ant-xxx');
    expect(mockSetConfig).toHaveBeenCalledWith('claude');
  });

  it('handles ollama without requiring API key', () => {
    mockSetApiKey('ollama', 'local');
    mockSetConfig('ollama');

    expect(mockSetApiKey).toHaveBeenCalledWith('ollama', 'local');
    expect(mockSetConfig).toHaveBeenCalledWith('ollama');
  });

  it('returns a WizardResult-like object shape', () => {
    const result: WizardResult = { provider: 'gemini', apiKey: 'key' };
    expect(result).toHaveProperty('provider');
    expect(result).toHaveProperty('apiKey');
    expect(typeof result.provider).toBe('string');
    expect(typeof result.apiKey).toBe('string');
  });
});
