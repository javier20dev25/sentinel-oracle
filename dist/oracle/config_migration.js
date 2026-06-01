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
Object.defineProperty(exports, "__esModule", { value: true });
exports.exportConfig = exportConfig;
exports.importConfig = importConfig;
exports.exportConfigToFile = exportConfigToFile;
exports.importConfigFromFile = importConfigFromFile;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const auth_1 = require("./auth");
const rules_1 = require("./rules");
const index_1 = require("./agents/index");
const tono_1 = require("./tono");
function exportConfig() {
    const config = (0, auth_1.getConfig)();
    const rules = (0, rules_1.listRules)();
    const tone = (0, tono_1.getCurrentTone)();
    const agent = (0, index_1.getCurrentAgent)();
    const providers = (0, auth_1.listProviders)();
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
function importConfig(config) {
    const warnings = [];
    try {
        if (config.provider) {
            (0, auth_1.setConfig)(config.provider, config.model);
        }
        if (config.tone) {
            const ok = (0, tono_1.setTone)(config.tone);
            if (!ok)
                warnings.push(`Unknown tone: "${config.tone}"`);
        }
        if (config.agent) {
            const ok = (0, index_1.setAgent)(config.agent);
            if (!ok)
                warnings.push(`Unknown agent: "${config.agent}"`);
        }
        if (config.rules && Array.isArray(config.rules)) {
            for (const rule of config.rules) {
                try {
                    (0, rules_1.addRule)(rule.name, rule.instruction);
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
function exportConfigToFile(filePath) {
    const config = exportConfig();
    const targetPath = filePath || path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel', 'oracle-config-export.json');
    const dir = path.dirname(targetPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(targetPath, JSON.stringify(config, null, 2), 'utf-8');
    return targetPath;
}
function importConfigFromFile(filePath) {
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
