import * as fs from 'fs';
import * as path from 'path';
const RULES_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel');
const RULES_FILE = path.join(RULES_DIR, 'rules.json');
function ensureFile() {
    if (!fs.existsSync(RULES_DIR))
        fs.mkdirSync(RULES_DIR, { recursive: true });
    if (!fs.existsSync(RULES_FILE))
        fs.writeFileSync(RULES_FILE, JSON.stringify([], null, 2), 'utf-8');
}
function readRules() {
    ensureFile();
    try {
        return JSON.parse(fs.readFileSync(RULES_FILE, 'utf-8'));
    }
    catch (_a) {
        return [];
    }
}
function writeRules(rules) {
    ensureFile();
    fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2), 'utf-8');
}
export function addRule(name, instruction) {
    const rules = readRules();
    const existing = rules.findIndex(r => r.name.toLowerCase() === name.toLowerCase());
    if (existing >= 0) {
        rules[existing] = { name, instruction, enabled: true, createdAt: rules[existing].createdAt };
    }
    else {
        rules.push({ name, instruction, enabled: true, createdAt: new Date().toISOString() });
    }
    writeRules(rules);
}
export function removeRule(name) {
    const rules = readRules();
    const idx = rules.findIndex(r => r.name.toLowerCase() === name.toLowerCase());
    if (idx < 0)
        return false;
    rules.splice(idx, 1);
    writeRules(rules);
    return true;
}
export function toggleRule(name, enabled) {
    const rules = readRules();
    const rule = rules.find(r => r.name.toLowerCase() === name.toLowerCase());
    if (!rule)
        return false;
    rule.enabled = enabled;
    writeRules(rules);
    return true;
}
export function listRules() {
    return readRules();
}
export function getActiveRulesText() {
    const rules = readRules().filter(r => r.enabled);
    if (rules.length === 0)
        return '';
    return rules.map(r => `[Custom Rule: ${r.name}] ${r.instruction}`).join('\n');
}
export function getDefaultRules() {
    return [
        {
            name: 'no-code-modification',
            instruction: 'You NEVER modify code, generate patches, or create "safe versions" of malicious code. You only analyze, explain, and recommend actions for the user to take manually.',
            enabled: true,
            createdAt: '2026-06-01T00:00:00.000Z',
        },
        {
            name: 'actionable-remediation',
            instruction: 'For every threat detected, you MUST explain: (1) what the threat does and why it matters, (2) how the user can verify it, (3) concrete steps to fix or mitigate it. Never just say "something suspicious was found."',
            enabled: true,
            createdAt: '2026-06-01T00:00:00.000Z',
        },
        {
            name: 'threat-correlation',
            instruction: 'When a scan finds threats, check the threat database for known malicious authors and patterns. If the author or pattern matches a known threat, escalate severity and explain the connection.',
            enabled: true,
            createdAt: '2026-06-01T00:00:00.000Z',
        },
        {
            name: 'evidence-requirements',
            instruction: 'Always cite specific code lines, package names, or PR diffs as evidence. Never make claims without showing the source. Use code blocks to show exact matches.',
            enabled: true,
            createdAt: '2026-06-01T00:00:00.000Z',
        },
    ];
}
export function ensureDefaultRules() {
    const rules = readRules();
    for (const def of getDefaultRules()) {
        if (!rules.find(r => r.name === def.name)) {
            rules.push(def);
        }
    }
    writeRules(rules);
}
