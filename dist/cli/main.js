#!/usr/bin/env node
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { LiteScanner } from '../core/lite/lite_scanner.js';
import { IntegrityManager } from './intelligence/integrity_manager.js';
import { SystemAuditor } from './intelligence/system_auditor.js';
import pc from 'picocolors';
import { oracleInteractive, oracleAsk } from '../oracle/command.js';
import { setApiKey, removeApiKey, listProviders, setConfig } from '../oracle/auth.js';
const program = new Command();
const scanner = new LiteScanner();
const auditor = new SystemAuditor();
const integrity = new IntegrityManager();
function preFlightCheck() {
    return __awaiter(this, void 0, void 0, function* () {
        const status = yield integrity.checkIntegrity();
        if (status.level !== 'TRUSTED') {
            integrity.report(status.level, status.reasons);
        }
        return status;
    });
}
program
    .name('sentinel')
    .version('4.0.0')
    .description('Sentinel Oracle Core — AI-powered security assistant (CLI 2)');
// --- Integrity check ---
program
    .command('integrity')
    .description('Check the integrity of Sentinel CLI and its local environment.')
    .option('--uptime', 'Show integrity chain with verified uptime counter')
    .option('--watch', 'Watch uptime in real-time (updates every second)')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    const status = yield integrity.checkIntegrity();
    integrity.report(status.level, status.reasons, options.uptime || options.watch);
    if (options.watch && status.level === 'TRUSTED') {
        const chain = integrity.getChain();
        console.log(pc.dim('   Watching integrity chain (Ctrl+C to stop)...\n'));
        const interval = setInterval(() => {
            const s = chain.getStatus();
            const elapsed = chain.formatDuration(s.accumulatedSeconds);
            process.stdout.write(`\r${pc.green('   🔗')} ${pc.white(elapsed)} ${pc.dim('verified uptime')}   `);
        }, 1000);
        process.on('SIGINT', () => {
            clearInterval(interval);
            process.stdout.write('\n');
            process.exit(0);
        });
    }
}));
// --- Doctor ---
program
    .command('doctor')
    .description('Perform a system health check for vulnerabilities and suspicious behavior.')
    .option('--deep', 'Perform deep behavioral analysis')
    .action((options) => __awaiter(void 0, void 0, void 0, function* () {
    yield preFlightCheck();
    yield auditor.runDoctor(options.deep);
}));
// --- Scan ---
program
    .command('scan')
    .description('Scan local directory or file for threats using 30 SAST rules.')
    .argument('[path]', 'Path to scan', '.')
    .option('--json', 'Output findings in JSON format')
    .action((targetPath, options) => __awaiter(void 0, void 0, void 0, function* () {
    const host = yield preFlightCheck();
    const fullPath = path.resolve(targetPath);
    if (!fs.existsSync(fullPath)) {
        console.error(pc.red(`Error: Path ${targetPath} does not exist.`));
        process.exit(1);
    }
    if (!options.json)
        console.log(pc.cyan(`\n🔍 Scanning ${targetPath}...`));
    let findings = [];
    if (fs.lstatSync(fullPath).isFile()) {
        const content = fs.readFileSync(fullPath, 'utf8');
        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
        findings = scanner.scanPatch(targetPath, patch);
    }
    else {
        const files = walkDir(fullPath).filter(f => f.endsWith('.js') || f.endsWith('.ts') || f.endsWith('.mjs'));
        for (const f of files) {
            const content = fs.readFileSync(f, 'utf8');
            const relPath = path.relative(fullPath, f);
            const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
            findings.push(...scanner.scanPatch(relPath, patch));
        }
    }
    if (options.json) {
        console.log(JSON.stringify({ host, findings }, null, 2));
    }
    else {
        if (findings.length === 0) {
            console.log(pc.green('✔ No threats detected.'));
        }
        else {
            findings.forEach(f => {
                console.log(pc.yellow(`  ■ [${f.severity}] ${f.type} in ${f.file}:${f.line}`));
                console.log(pc.dim(`    Evidence: ${f.snippet}`));
            });
            console.log(pc.cyan(`\n${findings.length} threat(s) found.\n`));
        }
    }
}));
// --- Oracle commands (CLI 2) ---
const oracle = program.command('oracle')
    .description('🧿 Oracle Core — AI-powered security assistant')
    .action(() => __awaiter(void 0, void 0, void 0, function* () {
    yield oracleInteractive();
}));
oracle
    .command('ask')
    .description('Ask a one-shot security question')
    .argument('<question...>', 'Your question')
    .action((question) => __awaiter(void 0, void 0, void 0, function* () {
    yield oracleAsk(question.join(' '));
}));
const auth = oracle
    .command('auth')
    .description('Manage provider API keys');
auth.command('set')
    .description('Set API key for a provider')
    .argument('<provider>', 'Provider name (gemini, claude, openai, ollama)')
    .argument('<key>', 'API key')
    .action((provider, key) => {
    setApiKey(provider, key);
    console.log(`\u2705 API key set for ${provider}`);
});
auth.command('remove')
    .description('Remove API key for a provider')
    .argument('<provider>', 'Provider name')
    .action((provider) => {
    removeApiKey(provider);
    console.log(`\u2705 API key removed for ${provider}`);
});
auth.command('list')
    .description('List configured providers')
    .action(() => {
    const providers = listProviders();
    if (providers.length === 0) {
        console.log('No providers configured.');
        return;
    }
    console.log('Configured providers:');
    providers.forEach(p => console.log(`  - ${p}`));
});
oracle
    .command('set-model')
    .description('Set default provider and model')
    .argument('<provider>', 'Provider name')
    .argument('[model]', 'Model name')
    .action((provider, model) => {
    setConfig(provider, model);
    console.log(`\u2705 Default provider set to ${provider}${model ? ` (model: ${model})` : ''}`);
});
oracle
    .command('interactive')
    .alias('chat')
    .description('Start interactive oracle session')
    .action(() => __awaiter(void 0, void 0, void 0, function* () {
    yield oracleInteractive();
}));
// --- Utilities ---
function walkDir(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        const lowerFile = file.toLowerCase();
        if (lowerFile === 'test' || lowerFile === 'tests' || lowerFile === 'example' ||
            lowerFile === 'examples' || lowerFile === 'benchmark' || lowerFile === 'docs' ||
            lowerFile === 'node_modules' || file.startsWith('.')) {
            return;
        }
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);
        if (stat && stat.isDirectory()) {
            results = results.concat(walkDir(fullPath));
        }
        else {
            results.push(fullPath);
        }
    });
    return results;
}
// --- Default: launch Oracle interactive ---
if (!process.argv.slice(2).length) {
    oracleInteractive().catch(console.error);
}
else {
    program.parse(process.argv);
}
