var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import * as readline from 'readline';
import * as pc from 'picocolors';
import { setApiKey, setConfig } from '../auth.js';
const PROVIDERS = [
    { id: 'gemini', name: 'Gemini', desc: 'google, fast, free tier available' },
    { id: 'claude', name: 'Claude', desc: 'anthropic, best for security analysis' },
    { id: 'openai', name: 'OpenAI', desc: 'gpt-4o, versatile' },
    { id: 'ollama', name: 'Ollama', desc: 'local, fully offline' },
];
function clearScreen() {
    process.stdout.write('\x1Bc');
}
function renderWelcomeBox() {
    const W = 52;
    const top = `${pc.cyan('╔')}${pc.cyan('═'.repeat(W))}${pc.cyan('╗')}`;
    const line1 = `${pc.cyan('║')}  ${pc.bold(pc.cyan('Sentinel Oracle'))}${' '.repeat(W - 22)}${pc.cyan('║')}`;
    const line2 = `${pc.cyan('║')}  ${pc.dim('AI-Powered Security Assistant')}${' '.repeat(W - 34)}${pc.cyan('║')}`;
    const bot = `${pc.cyan('╚')}${pc.cyan('═'.repeat(W))}${pc.cyan('╝')}`;
    console.log(`\n  ${top}\n  ${line1}\n  ${line2}\n  ${bot}\n`);
}
function renderProviderList() {
    console.log(`  ${pc.white('No AI provider configured yet. Let\'s set one up.')}\n`);
    PROVIDERS.forEach((p, i) => {
        const num = pc.cyan(`${i + 1}`);
        const name = pc.bold(pc.white(p.name));
        const desc = pc.dim(p.desc);
        console.log(`  ${num}) ${name}  ${desc}`);
    });
    console.log();
}
function maskedInput(prompt, providerId) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            const rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout,
            });
            let input = '';
            const isRaw = process.stdin.isRaw;
            try {
                process.stdin.setRawMode(true);
            }
            catch ( /* ok */_a) { /* ok */ }
            process.stdin.resume();
            process.stdout.write(`  ${prompt} `);
            const onData = (chunk) => {
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
                try {
                    process.stdin.setRawMode(false);
                }
                catch ( /* ok */_a) { /* ok */ }
                if (isRaw === false) {
                    try {
                        process.stdin.setRawMode(false);
                    }
                    catch ( /* ok */_b) { /* ok */ }
                }
                process.stdin.pause();
                rl.close();
            };
            process.stdin.on('data', onData);
        });
    });
}
export function providerWizard() {
    return __awaiter(this, void 0, void 0, function* () {
        clearScreen();
        renderWelcomeBox();
        renderProviderList();
        const selection = yield new Promise((resolve) => {
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
        let selected;
        const num = parseInt(selection, 10);
        if (!isNaN(num) && num >= 1 && num <= PROVIDERS.length) {
            selected = PROVIDERS[num - 1];
        }
        else {
            selected = PROVIDERS.find(p => p.id === selection || p.name.toLowerCase() === selection);
        }
        if (!selected) {
            console.log(`  ${pc.red(`Invalid selection: "${selection}".`)}`);
            console.log(`  ${pc.yellow('Please run the wizard again.')}\n`);
            return null;
        }
        console.log(`\n  ${pc.dim(`Provider: ${pc.bold(selected.name)}`)}\n`);
        let apiKey;
        if (selected.id === 'ollama') {
            apiKey = 'local';
        }
        else {
            apiKey = yield maskedInput(`Paste your ${selected.name} API key:`, selected.id);
            if (!apiKey) {
                console.log(`  ${pc.yellow('No API key entered. Exiting wizard.')}\n`);
                return null;
            }
        }
        setApiKey(selected.id, apiKey);
        setConfig(selected.id);
        console.log(`  ${pc.green('✓')} ${pc.bold(selected.name)} ${pc.green('configured successfully')}\n`);
        return { provider: selected.id, apiKey };
    });
}
