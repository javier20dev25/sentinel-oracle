"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SLASH_COMMANDS = exports.permissionCache = exports.currentMode = exports.conversationHistory = void 0;
exports.oracleInteractive = oracleInteractive;
exports.handleSlash = handleSlash;
exports.oracleAsk = oracleAsk;
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const child_process_1 = require("child_process");
const engine_1 = require("./engine");
const auth_1 = require("./auth");
const tools_1 = require("./tools");
const gh_guard_1 = require("./gh_guard");
const rules_1 = require("./rules");
const threat_db_1 = require("./threat_db");
const viz_1 = require("./viz");
const reports_1 = require("./reports");
const spinner_1 = require("./spinner");
const tono_1 = require("./tono");
const agents_1 = require("./agents");
const cli1_bridge_1 = require("./cli1_bridge");
const config_migration_1 = require("./config_migration");
const welcome_1 = require("./ui/welcome");
const renderer_1 = require("./ui/renderer");
const pc = __importStar(require("picocolors"));
exports.conversationHistory = [];
exports.currentMode = 'execute';
exports.permissionCache = new Set();
const spinner = new spinner_1.Spinner();
// ─── Raw Keypress Reader ──────────────────────────────────────
function readSingleKeypress() {
    return new Promise(resolve => {
        const wasRaw = process.stdin.isRaw;
        const wasPaused = process.stdin.isPaused();
        try {
            process.stdin.setRawMode(true);
            process.stdin.resume();
        }
        catch (_a) {
            resolve('enter');
            return;
        }
        const cb = (data) => {
            try {
                process.stdin.setRawMode(wasRaw || false);
            }
            catch (_a) { }
            if (!wasPaused)
                try {
                    process.stdin.pause();
                }
                catch (_b) { }
            process.stdin.removeListener('data', cb);
            const b = data[0];
            if (b === 0x0d || b === 0x0a)
                resolve('enter');
            else if (b === 0x1b)
                resolve('escape');
            else if (b === 0x61 || b === 0x41)
                resolve('auto');
            else if (b === 0x79 || b === 0x59)
                resolve('enter');
            else if (b === 0x6e || b === 0x4e)
                resolve('escape');
            else
                resolve('escape');
        };
        process.stdin.once('data', cb);
    });
}
// ─── Permission System ─────────────────────────────────────────
const permissionPrompt = (toolName, args) => __awaiter(void 0, void 0, void 0, function* () {
    if (exports.currentMode === 'auto')
        return true;
    const key = `${toolName}:${JSON.stringify(args)}`;
    if (exports.permissionCache.has(key))
        return true;
    const argStr = Object.entries(args)
        .map(([k, v]) => `${k}=${String(v).slice(0, 60)}`)
        .join(', ');
    console.log((0, viz_1.permissionBannerText)(toolName, argStr, exports.currentMode));
    const result = yield readSingleKeypress();
    if (result === 'auto') {
        exports.currentMode = 'auto';
        console.log(`\r  ${pc.green('(v)')} Auto-approve ${pc.bold('ON')}  all tools will run without prompting\n`);
        return true;
    }
    if (result === 'enter') {
        exports.permissionCache.add(key);
        console.log(`\r  ${pc.green('(v)')} Allowed\n`);
        return true;
    }
    console.log(`\r  ${pc.yellow('(x)')} Denied\n`);
    return false;
});
// ─── Readline Tab Completer ───────────────────────────────────
const SLASH_COMMANDS = [
    '/help', '/mode', '/mode plan', '/mode execute', '/mode auto',
    '/models', '/provider', '/tools', '/tools -v',
    '/guard', '/gh-login', '/repos',
    '/history', '/clear', '/auth', '/trust', '/trust clear',
    '/report md', '/report json',
    '/rule list', '/rule add', '/rule remove', '/rule toggle',
    '/threat list', '/threat query', '/threat auth', '/threat correlate',
    '/tono', '/agent', '/agent list', '/agent set',
    '/findings', '/audit',
    '/cli1', '/cli1-import',
    '/export config', '/import config',
];
exports.SLASH_COMMANDS = SLASH_COMMANDS;
function completer(line) {
    const hits = SLASH_COMMANDS.filter(c => c.startsWith(line) && c !== line);
    return [hits.length ? hits : SLASH_COMMANDS, line];
}
// ─── Help Text ─────────────────────────────────────────────────
function HELP_TEXT() {
    const tone = (0, tono_1.getCurrentTone)();
    return `
${pc.cyan('┌─────────────────────────────────────────────────────────────┐')}
${pc.cyan('│')}  ${pc.bold('Sentinel Oracle Core — Complete Guide')}                ${pc.cyan('│')}
${pc.cyan('│')}  ${pc.gray('CLI 2  ·  Multi-Provider  ·  Tool-Orchestrated  ·  Permissions')}  ${pc.cyan('│')}
${pc.cyan('└─────────────────────────────────────────────────────────────┘')}

${(0, viz_1.modeBanner)(exports.currentMode)}
  ${pc.gray('Tone:')} ${pc.bold(tone.label)} ${pc.gray('(' + tone.description + ')')}

${pc.bold('HOW TO USE')}
  Ask questions in natural language. The Oracle selects which tools
  to run based on your question. Use /mode to change behavior.

  Modes:
    ${pc.green('/mode plan')}     AI only suggests tools, never executes
    ${pc.green('/mode execute')}  AI runs tools with your approval
    ${pc.green('/mode auto')}     AI runs everything without asking

  Before running a tool, you see:
  ${pc.gray('\u2500'.repeat(50))}
    scan  path=./src
  ${pc.gray('\u2500'.repeat(50))}
    ${pc.green('Enter')} Allow    ${pc.red('Esc')} Deny    ${pc.cyan('A')} Auto-approve
  ${pc.gray('\u2500'.repeat(50))}

  Tab key shows available commands. Arrow keys cycle history.

${pc.bold('SLASH COMMANDS')}

  ${pc.green('/help')}               This guide
  ${pc.green('/mode')}               View current mode
  ${pc.green('/mode plan')}          Switch to plan mode
  ${pc.green('/mode execute')}       Switch to execute mode
  ${pc.green('/mode auto')}          Switch to auto mode
  ${pc.green('/tono')}               Interactive tone selector
  ${pc.green('/models')}             List providers and models
  ${pc.green('/provider')}           Show active configuration
  ${pc.green('/tools')}              List ${(0, tools_1.getToolDefs)().length} tools
  ${pc.green('/guard')}              Run connection security guard
  ${pc.green('/gh-login')}           Authenticate with GitHub via browser
  ${pc.green('/repos')} [n] [owner]  List repositories via gh

  ${pc.green('/history')}            Session statistics
  ${pc.green('/clear')}              Clear conversation history
  ${pc.green('/auth')}               Show configured API keys
  ${pc.green('/trust')}              Permission status
  ${pc.green('/trust clear')}        Clear permission cache

  ${pc.cyan('RULES')}
    ${pc.cyan('/rule list')}                    List active rules
    ${pc.cyan('/rule add')} <name> <ins>         Add a rule
    ${pc.cyan('/rule remove')} <name>            Remove a rule
    ${pc.cyan('/rule toggle')} <name>            Toggle a rule

  ${pc.yellow('THREAT DB')}
    ${pc.yellow('/threat list')} [n]             Last N threats
    ${pc.yellow('/threat query')} <author>       Search by author
    ${pc.yellow('/threat auth')}                 High-risk authors
    ${pc.yellow('/threat correlate')} <auth>     Correlate findings

  ${pc.magenta('REPORTS')}
    ${pc.magenta('/report md')} [file]           Markdown report
    ${pc.magenta('/report json')} [file]         JSON report

  ${pc.cyan('AGENTS')}
    ${pc.cyan('/agent')}                    Show current agent
    ${pc.cyan('/agent list')}               List available agents
    ${pc.cyan('/agent set')} <id>            Switch agent (blue/red/auditor/default)

  ${pc.green('FINDINGS & AUDIT')}
    ${pc.green('/findings')}                Show last scan results in formatted box
    ${pc.green('/audit')}                   Run local database audit

  ${pc.yellow('CLI 1 BRIDGE')}
    ${pc.yellow('/cli1')}                   Show CLI 1 detection status
    ${pc.yellow('/cli1-import')}            Import CLI 1 classified files

  ${pc.green('CONFIG MIGRATION')}
    ${pc.green('/export config')} [file]    Export configuration to JSON file
    ${pc.green('/import config')} <file>    Import configuration from JSON file

${pc.bold('AI RESTRICTIONS')}
  - Cannot modify code or generate patches
  - Cannot install packages (audit only via verify-pkg)
  - Cannot execute arbitrary commands (only defined tools)
  - Cannot ignore connection guard
  - Cannot claim safety without evidence

${pc.bold('COVER FORMAT')}
  [SEVERITY] Threat type
  Context: File/package/line
  Outcome: What an attacker can achieve
  Verification: How to confirm not a false positive
  Execution: Concrete steps to fix
  Reference: Related pattern or CVE
`;
}
// ─── Slash Command Handler ────────────────────────────────────
function handleSlash(input) {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        const parts = input.split(/\s+/);
        const cmd = parts[0].toLowerCase();
        switch (cmd) {
            case '/help': {
                console.log(HELP_TEXT());
                return true;
            }
            case '/tono': {
                const selected = yield (0, tono_1.selectToneModal)();
                if (selected) {
                    const tone = (0, tono_1.getCurrentTone)();
                    console.log(pc.green(`  Tone set to: ${pc.bold(tone.label)}`));
                }
                else {
                    console.log(pc.gray('  Tone selection cancelled.'));
                }
                return true;
            }
            case '/mode': {
                const sub = (_a = parts[1]) === null || _a === void 0 ? void 0 : _a.toLowerCase();
                if (sub === 'plan') {
                    exports.currentMode = 'plan';
                    console.log((0, viz_1.modeBanner)('plan') + '\n');
                    return true;
                }
                if (sub === 'execute') {
                    exports.currentMode = 'execute';
                    console.log((0, viz_1.modeBanner)('execute') + '\n');
                    return true;
                }
                if (sub === 'auto') {
                    exports.currentMode = 'auto';
                    console.log((0, viz_1.modeBanner)('auto') + '\n');
                    return true;
                }
                console.log((0, viz_1.modeBanner)(exports.currentMode) + '\n');
                return true;
            }
            case '/models': {
                const models = {
                    gemini: ['gemini-2.0-flash', 'gemini-2.0-pro', 'gemini-1.5-pro'],
                    claude: ['claude-sonnet-4-20250514', 'claude-3-opus-20240229', 'claude-3-haiku-20240307'],
                    openai: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'],
                    ollama: ['llama3', 'llama3.1', 'mistral', 'codellama', 'gemma2', 'phi3'],
                };
                console.log(pc.cyan('\n  Available Providers & Models:\n'));
                for (const [prov, mods] of Object.entries(models)) {
                    const configured = (0, auth_1.listProviders)().includes(prov);
                    const badge = configured ? pc.green('v') : pc.gray('.');
                    console.log(`  ${badge} ${pc.bold(prov)}`);
                    mods.forEach(m => console.log(`      ${pc.gray('-')} ${m}`));
                }
                console.log(pc.gray('\n  Configure with: sentinel oracle auth set <provider> <key>\n'));
                return true;
            }
            case '/provider': {
                const config = (0, auth_1.getConfig)();
                const configuredKeys = (0, auth_1.listProviders)();
                console.log(pc.cyan('\n  Provider Configuration:\n'));
                if (config.provider) {
                    console.log(`  Active:   ${pc.bold(config.provider)} ${config.model ? `(${config.model})` : ''}`);
                }
                else {
                    console.log(`  Active:   ${pc.yellow('none')}`);
                }
                console.log(`  Keys:     ${configuredKeys.length > 0 ? configuredKeys.join(', ') : pc.yellow('none')}`);
                console.log(`  Env vars: SENTINEL_PROVIDER, SENTINEL_GEMINI_KEY, SENTINEL_CLAUDE_KEY, SENTINEL_OPENAI_KEY\n`);
                return true;
            }
            case '/tools': {
                const defs = (0, tools_1.getToolDefs)();
                const verbose = parts[1] === '-v';
                console.log(pc.cyan(`\n  ${defs.length} Available Tools:\n`));
                for (const t of defs) {
                    const params = Object.keys(t.parameters.properties);
                    const paramStr = params.length > 0 ? params.map(p => `${p}?`).join(' ') : '(no args)';
                    console.log(`  ${pc.bold(t.name)} ${pc.gray(paramStr)}`);
                    if (verbose)
                        console.log(`      ${t.description}`);
                    console.log();
                }
                return true;
            }
            case '/repos': {
                try {
                    const limit = String(Math.min(Math.max(parseInt(parts[1]) || 10, 1), 100));
                    const safeOwner = parts.slice(2).join(' ').replace(/[^a-zA-Z0-9_.-]/g, '');
                    console.log(pc.gray(`\n  Fetching repos${safeOwner ? ` for ${safeOwner}` : ''}...`));
                    const args = ['repo', 'list'];
                    if (safeOwner)
                        args.push('--owner', safeOwner);
                    args.push('--limit', limit, '--json', 'name,owner,visibility,description');
                    const out = (0, child_process_1.execFileSync)('gh', args, { timeout: 15000, encoding: 'utf-8', windowsHide: true });
                    const repos = JSON.parse(out);
                    if (repos.length === 0) {
                        console.log(pc.yellow('  No repos found.\n'));
                    }
                    else {
                        console.log();
                        repos.forEach((r) => {
                            const vis = r.visibility === 'PUBLIC' ? pc.green('public') : pc.yellow('private');
                            console.log(`  ${pc.bold(r.owner.login + '/' + r.name)} ${vis}`);
                            if (r.description)
                                console.log(`    ${r.description}`);
                        });
                        console.log();
                    }
                }
                catch (e) {
                    console.log(pc.red(`  Error: ${e.message}\n`));
                }
                return true;
            }
            case '/history': {
                const sysCount = exports.conversationHistory.filter(m => m.role === 'system').length;
                const userCount = exports.conversationHistory.filter(m => m.role === 'user').length;
                const asstCount = exports.conversationHistory.filter(m => m.role === 'assistant').length;
                const toolCount = exports.conversationHistory.filter(m => m.role === 'tool').length;
                console.log(pc.cyan('\n  Session Statistics:\n'));
                console.log(`  Messages:   ${exports.conversationHistory.length}`);
                console.log(`  System:     ${sysCount}`);
                console.log(`  User:       ${userCount}`);
                console.log(`  Assistant:  ${asstCount}`);
                console.log(`  Tool calls: ${toolCount}`);
                console.log(`  Mode:       ${pc.bold(exports.currentMode.toUpperCase())}`);
                console.log(`  Tone:       ${pc.bold((0, tono_1.getCurrentTone)().label)}`);
                console.log(`  Perm cache: ${exports.permissionCache.size} tool(s) cached`);
                console.log(pc.gray('  Use /clear to reset.\n'));
                return true;
            }
            case '/clear': {
                exports.conversationHistory = [];
                exports.permissionCache.clear();
                console.log(pc.gray('  History and permission cache cleared.\n'));
                return true;
            }
            case '/guard': {
                console.log(pc.gray('\n  Running connection security guard...'));
                const report = (0, gh_guard_1.runGuard)();
                console.log('\n' + (0, gh_guard_1.formatGuardReport)(report) + '\n');
                return true;
            }
            case '/gh-login': {
                console.log(pc.cyan('\n  GitHub Login'));
                console.log(pc.gray('  Opening browser to authenticate with GitHub...\n'));
                const guard = (0, gh_guard_1.runGuard)();
                if (guard.passed) {
                    const user = guard.auth.detail;
                    console.log(pc.green(`  Already authenticated: ${user}\n`));
                    return true;
                }
                const result = yield (0, gh_guard_1.ghLogin)();
                if (result.success) {
                    console.log(pc.green(`  Login successful: ${result.username || 'authenticated'}\n`));
                }
                else {
                    console.log(pc.red(`  Login failed: ${result.message}\n`));
                    console.log(pc.gray('  Alternative: run "gh auth login" in your terminal\n'));
                }
                return true;
            }
            case '/auth': {
                const keys = (0, auth_1.listProviders)();
                console.log(pc.cyan('\n  Authentication Status:\n'));
                if (keys.length === 0) {
                    console.log(pc.yellow('  No API keys configured.\n'));
                }
                else {
                    keys.forEach(k => console.log(`  [OK] ${k}: key set`));
                    console.log();
                }
                return true;
            }
            case '/report': {
                const format = (parts[1] || 'md').toLowerCase();
                const filename = parts[2];
                const ext = format === 'json' ? 'json' : 'md';
                const findings = [];
                for (const m of exports.conversationHistory.filter(m => m.role === 'tool')) {
                    const parsed = (0, reports_1.parseFindingsFromOutput)(m.content, 'scan');
                    findings.push(...parsed);
                }
                const severities = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
                for (const f of findings) {
                    const s = f.severity.toUpperCase();
                    if (severities[s] !== undefined)
                        severities[s]++;
                }
                const totalFindings = findings.length;
                const verdict = totalFindings === 0 ? 'SAFE' : severities.CRITICAL > 0 ? 'MALICIOUS' : 'SUSPICIOUS';
                const config = (0, auth_1.getConfig)();
                const reportData = {
                    title: `Security Analysis — ${new Date().toLocaleDateString()}`,
                    date: new Date().toISOString(),
                    provider: config.provider || undefined,
                    model: config.model || undefined,
                    findings,
                    summary: { totalFindings, severities, verdict },
                    conversation: exports.conversationHistory.map(m => ({
                        role: m.role,
                        content: m.content.length > 500 ? m.content.slice(0, 500) + '...' : m.content,
                    })),
                };
                const safeName = filename || `oracle-report-${Date.now()}.${ext}`;
                const content = format === 'json' ? (0, reports_1.generateJSON)(reportData) : (0, reports_1.generateMarkdown)(reportData);
                const filePath = (0, reports_1.saveReport)(content, safeName);
                console.log(pc.green(`\n  [OK] Report saved: ${filePath}\n`));
                return true;
            }
            case '/trust': {
                const sub = (_b = parts[1]) === null || _b === void 0 ? void 0 : _b.toLowerCase();
                if (sub === 'clear') {
                    exports.permissionCache.clear();
                    console.log(pc.green('  [OK] Permission cache cleared.\n'));
                    return true;
                }
                console.log(pc.cyan('\n  Permission Status:\n'));
                console.log(`  Mode:      ${pc.bold(exports.currentMode.toUpperCase())}`);
                console.log(`  Cached:    ${exports.permissionCache.size} tool(s) approved`);
                if (exports.permissionCache.size > 0) {
                    for (const k of exports.permissionCache) {
                        console.log(`    ${pc.gray('.')} ${k}`);
                    }
                }
                console.log();
                return true;
            }
            case '/findings': {
                const toolMessages = exports.conversationHistory.filter(m => m.role === 'tool');
                if (toolMessages.length === 0) {
                    console.log(pc.yellow('\n  No tool output in current session.\n'));
                    return true;
                }
                const last = toolMessages[toolMessages.length - 1];
                const contentLines = last.content.split('\n').filter(l => l.trim());
                // Determine severity from content
                const hasCritical = contentLines.some(l => l.includes('CRITICAL'));
                const hasHigh = contentLines.some(l => l.includes('HIGH'));
                const severity = hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'INFO';
                const toolName = last.tool_call_id || 'scan';
                const displayLines = contentLines.slice(0, 25).map(l => l.replace(/⟨⟨⟨SENTINEL_DATA⟩⟩⟩/g, '').replace(/⟨⟨⟨\/SENTINEL_DATA⟩⟩⟩/g, '').trim()).filter(l => l);
                console.log((0, viz_1.findingsBox)(`Last Tool Output: ${toolName}`, displayLines, severity));
                return true;
            }
            case '/audit': {
                const rules = (0, rules_1.listRules)();
                const threats = (0, threat_db_1.getRecentThreats)(10);
                console.log(pc.cyan('\n  Local Database Audit:\n'));
                console.log(`  Rules:       ${rules.length} (${rules.filter(r => r.enabled).length} enabled)`);
                console.log(`  Threats DB:  ${'~/.sentinel/threats.db'}`);
                console.log(`  Recent threats: ${threats.length}`);
                console.log(`  Permissions: ${exports.permissionCache.size} cached tools`);
                console.log(`  Mode:        ${exports.currentMode}`);
                console.log(`  Tone:        ${(0, tono_1.getCurrentTone)().label}`);
                console.log(`  Agent:       ${(0, agents_1.getCurrentAgent)().name}`);
                console.log(`  History:     ${exports.conversationHistory.length} messages`);
                const dbOk = fs.existsSync(path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel'));
                console.log(`  Config dir:  ${dbOk ? pc.green('OK') : pc.yellow('not found')}`);
                console.log();
                return true;
            }
            case '/agent': {
                const sub = (_c = parts[1]) === null || _c === void 0 ? void 0 : _c.toLowerCase();
                if (sub === 'list') {
                    console.log(pc.cyan('\n  Available Agents:\n'));
                    for (const a of agents_1.AGENTS) {
                        const active = a.id === (0, agents_1.getCurrentAgent)().id ? pc.green(' *') : '  ';
                        console.log(`  ${active} ${a.icon} ${pc.bold(a.name)}`);
                        console.log(`      ${a.description}`);
                        console.log();
                    }
                    console.log(pc.gray('  Use /agent set <id> to switch.\n'));
                    return true;
                }
                if (sub === 'set') {
                    const id = (_d = parts[2]) === null || _d === void 0 ? void 0 : _d.toLowerCase();
                    if (!id) {
                        console.log(pc.yellow('  Usage: /agent set <id>\n'));
                        return true;
                    }
                    if ((0, agents_1.setAgent)(id)) {
                        const agent = (0, agents_1.getCurrentAgent)();
                        console.log(pc.green(`  [OK] Agent switched to: ${pc.bold(agent.name)} — ${agent.description}\n`));
                    }
                    else {
                        console.log(pc.yellow(`  Unknown agent: ${id}. Try: /agent list\n`));
                    }
                    return true;
                }
                const agent = (0, agents_1.getCurrentAgent)();
                console.log(pc.cyan('\n  Current Agent:\n'));
                console.log(`  ${agent.icon} ${pc.bold(agent.name)}`);
                console.log(`  ${agent.description}\n`);
                console.log(pc.gray('  Use /agent list to see all agents.\n'));
                return true;
            }
            case '/cli1': {
                const data = (0, cli1_bridge_1.detectCli1)();
                console.log(pc.cyan('\n  CLI 1 Bridge:\n'));
                console.log((0, cli1_bridge_1.formatCli1Report)(data));
                console.log();
                return true;
            }
            case '/cli1-import': {
                const result = (0, cli1_bridge_1.importCli1Classified)();
                if (result.imported > 0) {
                    console.log(pc.green(`\n  [OK] Imported ${result.imported} classified files from CLI 1.\n`));
                    result.files.slice(0, 10).forEach(f => console.log(`    ${pc.gray('-')} ${f}`));
                    if (result.files.length > 10)
                        console.log(pc.gray(`    ... and ${result.files.length - 10} more`));
                    console.log();
                }
                else {
                    console.log(pc.yellow('\n  No classified files found in CLI 1.\n'));
                }
                return true;
            }
            case '/rule': {
                const sub = (_e = parts[1]) === null || _e === void 0 ? void 0 : _e.toLowerCase();
                if (sub === 'list' || !sub) {
                    const rules = (0, rules_1.listRules)();
                    console.log(pc.cyan('\n  Custom Rules:\n'));
                    if (rules.length === 0) {
                        console.log(pc.yellow('  No custom rules. Defaults will be created on first chat.\n'));
                    }
                    else {
                        for (const r of rules) {
                            const status = r.enabled ? pc.green('v') : pc.gray('x');
                            console.log(`  ${status} ${pc.bold(r.name)}`);
                            console.log(`      ${r.instruction}`);
                            console.log(`      ${pc.gray(r.createdAt)}\n`);
                        }
                    }
                    return true;
                }
                if (sub === 'add') {
                    const name = parts[2];
                    const instruction = parts.slice(3).join(' ');
                    if (!name || !instruction) {
                        console.log(pc.yellow('  Usage: /rule add <name> <instruction>\n'));
                        return true;
                    }
                    (0, rules_1.addRule)(name, instruction);
                    console.log(pc.green(`  [OK] Rule "${name}" added.\n`));
                    return true;
                }
                if (sub === 'remove') {
                    const name = parts[2];
                    if (!name) {
                        console.log(pc.yellow('  Usage: /rule remove <name>\n'));
                        return true;
                    }
                    if ((0, rules_1.removeRule)(name))
                        console.log(pc.green(`  [OK] Rule "${name}" removed.\n`));
                    else
                        console.log(pc.yellow(`  Rule "${name}" not found.\n`));
                    return true;
                }
                if (sub === 'toggle') {
                    const name = parts[2];
                    if (!name) {
                        console.log(pc.yellow('  Usage: /rule toggle <name>\n'));
                        return true;
                    }
                    const rules = (0, rules_1.listRules)();
                    const rule = rules.find(r => r.name.toLowerCase() === name.toLowerCase());
                    if (!rule) {
                        console.log(pc.yellow(`  Rule "${name}" not found.\n`));
                        return true;
                    }
                    (0, rules_1.toggleRule)(name, !rule.enabled);
                    console.log(pc.green(`  [OK] Rule "${name}" ${rule.enabled ? 'disabled' : 'enabled'}.\n`));
                    return true;
                }
                return false;
            }
            case '/threat': {
                const sub = (_f = parts[1]) === null || _f === void 0 ? void 0 : _f.toLowerCase();
                if (sub === 'list' || !sub) {
                    const n = parseInt(parts[2]) || 10;
                    const threats = (0, threat_db_1.getRecentThreats)(n);
                    console.log(pc.cyan(`\n  Recent Threats (last ${n}):\n`));
                    if (threats.length === 0) {
                        console.log(pc.gray('  No threats recorded yet.\n'));
                    }
                    else {
                        for (const t of threats) {
                            const sev = t.severity === 'CRITICAL' ? pc.red('CRITICAL') :
                                t.severity === 'HIGH' ? pc.yellow('HIGH') : pc.gray(t.severity || 'MEDIUM');
                            console.log(`  #${t.id} ${sev}`);
                            console.log(`      Type:   ${t.type}  Source: ${t.source}`);
                            console.log(`      Author: ${t.author || 'unknown'}  Date: ${t.detected_at}`);
                            if (t.title)
                                console.log(`      Title:  ${t.title}`);
                            console.log();
                        }
                    }
                    return true;
                }
                if (sub === 'query') {
                    const author = parts.slice(2).join(' ');
                    if (!author) {
                        console.log(pc.yellow('  Usage: /threat query <author>\n'));
                        return true;
                    }
                    const threats = (0, threat_db_1.getThreatsByAuthor)(author);
                    const ta = (0, threat_db_1.getThreatAuthor)(author);
                    console.log(pc.cyan(`\n  Threat Intelligence: ${author}\n`));
                    if (ta) {
                        console.log(`  Risk Level: ${ta.risk_level === 'CRITICAL' ? pc.red('CRITICAL') : ta.risk_level === 'HIGH' ? pc.yellow('HIGH') : ta.risk_level}`);
                        console.log(`  First seen: ${ta.first_seen}`);
                        console.log(`  Last seen:  ${ta.last_seen}`);
                        console.log(`  Threats:    ${ta.threat_count}`);
                        console.log();
                    }
                    if (threats.length === 0)
                        console.log(pc.gray('  No threats found for this author.\n'));
                    else {
                        for (const t of threats)
                            console.log(`  #${t.id} ${t.type} — ${t.source} — ${t.detected_at}`);
                        console.log();
                    }
                    return true;
                }
                if (sub === 'auth') {
                    const authors = (0, threat_db_1.getHighRiskAuthors)();
                    console.log(pc.cyan('\n  High-Risk Authors:\n'));
                    if (authors.length === 0)
                        console.log(pc.gray('  No high-risk authors recorded.\n'));
                    else {
                        for (const a of authors) {
                            const level = a.risk_level === 'CRITICAL' ? pc.red('CRITICAL') : pc.yellow('HIGH');
                            console.log(`  ${level} ${pc.bold(a.author)} — ${a.threat_count} threat(s) — last: ${a.last_seen}`);
                        }
                        console.log();
                    }
                    return true;
                }
                if (sub === 'correlate') {
                    const author = parts.slice(2).join(' ');
                    if (!author) {
                        console.log(pc.yellow('  Usage: /threat correlate <author>\n'));
                        return true;
                    }
                    const corr = (0, threat_db_1.correlateFindings)(author, '', '');
                    console.log(pc.cyan(`\n  Correlation for "${author}":\n`));
                    console.log(`  Known author:    ${corr.knownAuthor ? pc.yellow('YES') : pc.green('No')}`);
                    console.log(`  Threat count:    ${corr.threatCount}`);
                    if (corr.knownAuthor) {
                        console.log(`  Risk level:      ${corr.authorRiskLevel}`);
                        console.log(`  Previous threats: ${corr.authorThreats.length}`);
                    }
                    console.log();
                    return true;
                }
                return false;
            }
            case '/export': {
                const sub = (_g = parts[1]) === null || _g === void 0 ? void 0 : _g.toLowerCase();
                if (sub === 'config') {
                    const filePath = parts[2];
                    const result = (0, config_migration_1.exportConfigToFile)(filePath || undefined);
                    console.log(pc.green(`\n  [OK] Configuration exported to: ${result}\n`));
                    return true;
                }
                return false;
            }
            case '/import': {
                const sub = (_h = parts[1]) === null || _h === void 0 ? void 0 : _h.toLowerCase();
                if (sub === 'config') {
                    const filePath = parts[2];
                    if (!filePath) {
                        console.log(pc.yellow('  Usage: /import config <filepath>\n'));
                        return true;
                    }
                    const result = (0, config_migration_1.importConfigFromFile)(filePath);
                    if (result.success) {
                        console.log(pc.green('\n  [OK] Configuration imported successfully.\n'));
                        if (result.warnings.length > 0) {
                            for (const w of result.warnings) {
                                console.log(pc.yellow(`  Warning: ${w}`));
                            }
                            console.log();
                        }
                    }
                    else {
                        console.log(pc.red(`\n  Error importing config: ${result.warnings.join(', ')}\n`));
                    }
                    return true;
                }
                return false;
            }
            default:
                return false;
        }
    });
}
// ─── Interactive Mode ─────────────────────────────────────────
function captureOutput(fn) {
    const chunks = [];
    const origLog = console.log;
    const origWrite = process.stdout.write.bind(process.stdout);
    console.log = (...args) => {
        chunks.push(args.map(a => String(a)).join(' ') + '\n');
    };
    process.stdout.write = (chunk, ...rest) => {
        chunks.push(String(chunk));
        return true;
    };
    const restore = () => {
        console.log = origLog;
        process.stdout.write = origWrite;
    };
    const result = fn().finally(restore);
    return { result, captured: () => chunks.join('').trim() };
}
function oracleInteractive() {
    return __awaiter(this, void 0, void 0, function* () {
        yield preFlightCheck();
        yield (0, rules_1.ensureDefaultRules)();
        // Run GitHub check (non-blocking, fire and forget)
        (0, welcome_1.welcomeSequence)().catch(() => { });
        // Launch Ink UI
        const { waitUntilExit } = (0, renderer_1.startUI)();
        yield waitUntilExit;
    });
}
function preFlightCheck() {
    const integrityOk = true; // placeholder — could check sentinel integrity
    if (!integrityOk) {
        console.log(pc.yellow('  Warning: Integrity check skipped.'));
    }
}
function oracleAsk(question) {
    return __awaiter(this, void 0, void 0, function* () {
        const provider = (0, engine_1.getDefaultProvider)();
        if (!provider) {
            console.log(pc.yellow('No provider configured.'));
            console.log(pc.gray('Run: sentinel oracle auth set <provider> <key>'));
            return;
        }
        try {
            spinner.start('Processing...', 'processing');
            const { response } = yield (0, engine_1.oracleChat)(question, exports.conversationHistory, provider, undefined, 'auto');
            spinner.stop();
            console.log(response);
        }
        catch (e) {
            spinner.stop();
            console.log(pc.red(`Error: ${e.message}`));
        }
    });
}
