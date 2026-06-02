var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as pc from 'picocolors';
import { getConfig } from '../auth.js';
import { checkGitHubLogin } from './github.js';
import { providerWizard } from './wizard.js';
function clearScreen() {
    process.stdout.write('\x1Bc');
}
function renderHeader() {
    const W = 60;
    const top = `${pc.cyan('╔')}${pc.cyan('═'.repeat(W))}${pc.cyan('╗')}`;
    const line1 = `${pc.cyan('║')}  ${pc.bold(pc.cyan('Sentinel Oracle'))}${' '.repeat(W - 20)}${pc.cyan('║')}`;
    const line2 = `${pc.cyan('║')}  ${pc.dim('AI-Powered Security Assistant')}${' '.repeat(W - 34)}${pc.cyan('║')}`;
    const line3 = `${pc.cyan('║')}  ${pc.dim('CLI 2  ·  Multi-Provider  ·  Tool-Orchestrated')}${' '.repeat(W - 50)}${pc.cyan('║')}`;
    const bot = `${pc.cyan('╚')}${pc.cyan('═'.repeat(W))}${pc.cyan('╝')}`;
    console.log(`\n  ${top}\n  ${line1}\n  ${line2}\n  ${line3}\n  ${bot}\n`);
}
function renderSummary(provider, model) {
    console.log(`  ${pc.dim('─'.repeat(60))}`);
    if (provider) {
        console.log(`  ${pc.green('✓')} ${pc.dim('Provider:')} ${pc.bold(pc.white(provider))}${model ? pc.dim(` | Model: ${model}`) : ''}`);
    }
    else {
        console.log(`  ${pc.yellow('!')} ${pc.dim('No provider configured — limited functionality')}`);
    }
    console.log(`  ${pc.dim('─'.repeat(60))}\n`);
}
function renderTips() {
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
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
export function welcomeSequence() {
    return __awaiter(this, void 0, void 0, function* () {
        clearScreen();
        renderHeader();
        yield checkGitHubLogin();
        const config = getConfig();
        let provider = config.provider;
        if (!provider) {
            const result = yield providerWizard();
            if (result) {
                provider = result.provider;
            }
        }
        renderSummary(provider, config.model);
        renderTips();
        yield sleep(1500);
    });
}
