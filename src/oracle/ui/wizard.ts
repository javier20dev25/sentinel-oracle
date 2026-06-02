import * as readline from 'readline';
import * as pc from 'picocolors';
import { setApiKey, setConfig, getApiKey, getConfig } from '../auth';

export interface WizardResult {
  provider: string;
  apiKey: string;
}

const PROVIDERS = [
  { id: 'gemini', name: 'Gemini', desc: 'google, fast, free tier available' },
  { id: 'claude', name: 'Claude', desc: 'anthropic, best for security analysis' },
  { id: 'openai', name: 'OpenAI', desc: 'gpt-4o, versatile' },
  { id: 'ollama', name: 'Ollama', desc: 'local, fully offline' },
];

function clearScreen(): void {
  process.stdout.write('\x1Bc');
}

function renderWelcomeBox(): void {
  const W = 52;
  const top = `${pc.cyan('╔')}${pc.cyan('═'.repeat(W))}${pc.cyan('╗')}`;
  const line1 = `${pc.cyan('║')}  ${pc.bold(pc.cyan('Sentinel Oracle'))}${' '.repeat(W - 22)}${pc.cyan('║')}`;
  const line2 = `${pc.cyan('║')}  ${pc.dim('AI-Powered Security Assistant')}${' '.repeat(W - 34)}${pc.cyan('║')}`;
  const bot = `${pc.cyan('╚')}${pc.cyan('═'.repeat(W))}${pc.cyan('╝')}`;
  console.log(`\n  ${top}\n  ${line1}\n  ${line2}\n  ${bot}\n`);
}

function renderProviderList(): void {
  console.log(`  ${pc.white('No AI provider configured yet. Let\'s set one up.')}\n`);
  PROVIDERS.forEach((p, i) => {
    const num = pc.cyan(`${i + 1}`);
    const name = pc.bold(pc.white(p.name));
    const desc = pc.dim(p.desc);
    console.log(`  ${num}) ${name}  ${desc}`);
  });
  console.log();
}

async function maskedInput(prompt: string, providerId: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    let input = '';
    const isRaw = process.stdin.isRaw;
    try { process.stdin.setRawMode(true); } catch { /* ok */ }
    process.stdin.resume();

    process.stdout.write(`  ${prompt} `);

    const onData = (chunk: Buffer) => {
      const char = chunk.toString();
      if (char === '\r' || char === '\n') {
        cleanup();
        process.stdout.write('\n');
        resolve(input);
        return;
      }
      if (char === '\x03') {
        cleanup();
        process.stdout.write('\n');
        resolve('');
        return;
      }
      if (char === '\x7f' || char === '\b') {
        if (input.length > 0) {
          input = input.slice(0, -1);
          process.stdout.write('\b \b');
        }
        return;
      }
      input += char;
      const masked = '*'.repeat(Math.max(0, input.length - 4)) + input.slice(-4);
      process.stdout.write('\r' + ' '.repeat(80) + '\r');
      process.stdout.write(`  ${prompt} ${masked}`);
    };

    const cleanup = () => {
      process.stdin.removeListener('data', onData);
      try { process.stdin.setRawMode(false); } catch { /* ok */ }
      if (isRaw === false) { try { process.stdin.setRawMode(false); } catch { /* ok */ } }
      process.stdin.pause();
      rl.close();
    };

    process.stdin.on('data', onData);
  });
}

export async function providerWizard(): Promise<WizardResult | null> {
  clearScreen();
  renderWelcomeBox();

  renderProviderList();

  const selection = await new Promise<string>((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });
    rl.question(`  ${pc.cyan('Enter number or name')} ${pc.dim('(1-4)')}: `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });

  if (!selection) {
    console.log(`  ${pc.yellow('No provider selected. Exiting wizard.')}\n`);
    return null;
  }

  let selected: typeof PROVIDERS[0] | undefined;
  const num = parseInt(selection, 10);
  if (!isNaN(num) && num >= 1 && num <= PROVIDERS.length) {
    selected = PROVIDERS[num - 1];
  } else {
    selected = PROVIDERS.find(p => p.id === selection || p.name.toLowerCase() === selection);
  }

  if (!selected) {
    console.log(`  ${pc.red(`Invalid selection: "${selection}".`)}`);
    console.log(`  ${pc.yellow('Please run the wizard again.')}\n`);
    return null;
  }

  console.log(`\n  ${pc.dim(`Provider: ${pc.bold(selected.name)}`)  }\n`);

  let apiKey: string;
  if (selected.id === 'ollama') {
    apiKey = 'local';
  } else {
    apiKey = await maskedInput(`Paste your ${selected.name} API key:`, selected.id);
    if (!apiKey) {
      console.log(`  ${pc.yellow('No API key entered. Exiting wizard.')}\n`);
      return null;
    }
  }

  setApiKey(selected.id, apiKey);
  setConfig(selected.id);

  console.log(`  ${pc.green('✓')} ${pc.bold(selected.name)} ${pc.green('configured successfully')}\n`);

  return { provider: selected.id, apiKey };
}
