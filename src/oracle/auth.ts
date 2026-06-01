import * as fs from 'fs';
import * as path from 'path';

const CONFIG_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

interface Config {
  provider?: string;
  model?: string;
  keys?: Record<string, string>;
}

function setSecurePermissions(filePath: string): void {
  try {
    if (process.platform !== 'win32') {
      fs.chmodSync(filePath, 0o600);
    }
  } catch {
    // non-fatal on platforms where chmod is unavailable
  }
}

function ensureConfig(): void {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    setSecurePermissions(CONFIG_DIR);
  }
  if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({ keys: {} }, null, 2), 'utf-8');
    setSecurePermissions(CONFIG_FILE);
  }
}

function readConfig(): Config {
  ensureConfig();
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
}

function writeConfig(config: Config): void {
  ensureConfig();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
  setSecurePermissions(CONFIG_FILE);
}

export function getApiKey(provider: string): string {
  const envMap: Record<string, string> = {
    gemini: 'SENTINEL_GEMINI_KEY',
    claude: 'SENTINEL_CLAUDE_KEY',
    openai: 'SENTINEL_OPENAI_KEY',
  };
  const envVar = envMap[provider];
  if (envVar && process.env[envVar]) return process.env[envVar]!;

  const config = readConfig();
  if (config.keys?.[provider]) return config.keys[provider]!;

  return '';
}

export function setApiKey(provider: string, key: string): void {
  const config = readConfig();
  if (!config.keys) config.keys = {};
  config.keys[provider] = key;
  writeConfig(config);
}

export function removeApiKey(provider: string): void {
  const config = readConfig();
  if (config.keys) delete config.keys[provider];
  writeConfig(config);
}

export function listProviders(): string[] {
  return Object.keys(readConfig().keys || {});
}

export function getConfig(): { provider?: string; model?: string } {
  const config = readConfig();
  return { provider: config.provider, model: config.model };
}

export function setConfig(provider: string, model?: string): void {
  const config = readConfig();
  config.provider = provider;
  if (model) config.model = model;
  writeConfig(config);
}
