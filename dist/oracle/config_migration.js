import * as fs from 'fs';
import * as path from 'path';
import { getConfig, setConfig, listProviders } from './auth.js';
import { listRules, addRule } from './rules.js';
import { getCurrentAgent, setAgent } from './agents/index.js';
import { getCurrentTone, setTone } from './tono.js';
export function exportConfig() {
    const config = getConfig();
    const rules = listRules();
    const tone = getCurrentTone();
    const agent = getCurrentAgent();
    const providers = listProviders();
    return {
        version: '4.0.0',
        exportedAt: new Date().toISOString(),
        provider: config.provider,
        model: config.model,
        tone: tone.id,
        agent: agent.id,
        rules: rules.map(r => ({
            name: r.name,
            instruction: r.instruction,
            enabled: r.enabled,
        })),
        hasKeys: providers.length > 0,
    };
}
export function importConfig(config) {
    const warnings = [];
    try {
        if (config.provider) {
            setConfig(config.provider, config.model);
        }
        if (config.tone) {
            const ok = setTone(config.tone);
            if (!ok)
                warnings.push(`Unknown tone: "${config.tone}"`);
        }
        if (config.agent) {
            const ok = setAgent(config.agent);
            if (!ok)
                warnings.push(`Unknown agent: "${config.agent}"`);
        }
        if (config.rules && Array.isArray(config.rules)) {
            for (const rule of config.rules) {
                try {
                    addRule(rule.name, rule.instruction);
                }
                catch (_a) {
                    warnings.push(`Failed to add rule: "${rule.name}"`);
                }
            }
        }
        return { success: true, warnings };
    }
    catch (e) {
        return { success: false, warnings: [e.message] };
    }
}
export function exportConfigToFile(filePath) {
    const config = exportConfig();
    const targetPath = filePath || path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel', 'oracle-config-export.json');
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(targetPath, JSON.stringify(config, null, 2), 'utf-8');
    return targetPath;
}
export function importConfigFromFile(filePath) {
    try {
        const raw = fs.readFileSync(filePath, 'utf-8');
        const config = JSON.parse(raw);
        if (!config.version || !config.tone || !config.agent) {
            return { success: false, warnings: ['Invalid config file: missing required fields'] };
        }
        return importConfig(config);
    }
    catch (e) {
        return { success: false, warnings: [e.message] };
    }
}
