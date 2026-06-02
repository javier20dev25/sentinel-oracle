import * as pc from 'picocolors';
import { getConfig } from '../auth';
import { checkGitHubLogin } from './github';
import { providerWizard } from './wizard';

function clearScreen(): void {
  process.stdout.write('\x1Bc');
}

function renderHeader(): void {
  const W = 60;
  const top = `${pc.cyan('╔')}${pc.cyan('═'.repeat(W))}${pc.cyan('╗')}`;
  const line1 = `${pc.cyan('║')}  ${pc.bold(pc.cyan('Sentinel Oracle'))}${' '.repeat(W - 20)}${pc.cyan('║')}`;
  const line2 = `${pc.cyan('║')}  ${pc.dim('AI-Powered Security Assistant')}${' '.repeat(W - 34)}${pc.cyan('║')}`;
  const line3 = `${pc.cyan('║')}  ${pc.dim('CLI 2  ·  Multi-Provider  ·  Tool-Orchestrated')}${' '.repeat(W - 50)}${pc.cyan('║')}`;
  const bot = `${pc.cyan('╚')}${pc.cyan('═'.repeat(W))}${pc.cyan('╝')}`;
  console.log(`\n  ${top}\n  ${line1}\n  ${line2}\n  ${line3}\n  ${bot}\n`);
}

function renderSummary(provider?: string, model?: string): void {
  console.log(`  ${pc.dim('─'.repeat(60))}`);
  if (provider) {
    console.log(`  ${pc.green('✓')} ${pc.dim('Provider:')} ${pc.bold(pc.white(provider))}${model ? pc.dim(` | Model: ${model}`) : ''}`);
  } else {
    console.log(`  ${pc.yellow('!')} ${pc.dim('No provider configured — limited functionality')}`);
  }
  console.log(`  ${pc.dim('─'.repeat(60))}\n`);
}

function renderTips(): void {
  console.log(`  ${pc.bold(pc.white('Getting Started'))}\n`);
  const tips = [
    `${pc.cyan('•')} ${pc.dim('"analyze package axios"')}`,
    `${pc.cyan('•')} ${pc.dim('"review a GitHub PR"')}`,
    `${pc.cyan('•')} ${pc.dim('"explain CVE-2024-3094"')}`,
    `${pc.cyan('•')} ${pc.dim('"audit dependencies"')}`,
  ];
  tips.forEach(t => console.log(`  ${t}`));
  console.log();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export async function welcomeSequence(): Promise<void> {
  clearScreen();
  renderHeader();

  await checkGitHubLogin();

  const config = getConfig();
  let provider = config.provider;

  if (!provider) {
    const result = await providerWizard();
    if (result) {
      provider = result.provider;
    }
  }

  renderSummary(provider, config.model);
  renderTips();

  await sleep(1500);
}
