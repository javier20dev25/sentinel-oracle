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
exports.getApiKey = getApiKey;
exports.setApiKey = setApiKey;
exports.removeApiKey = removeApiKey;
exports.listProviders = listProviders;
exports.getConfig = getConfig;
exports.setConfig = setConfig;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const CONFIG_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
function setSecurePermissions(filePath) {
    try {
        if (process.platform !== 'win32') {
            fs.chmodSync(filePath, 0o600);
        }
    }
    catch (_a) {
        // non-fatal on platforms where chmod is unavailable
    }
}
function ensureConfig() {
    if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
        setSecurePermissions(CONFIG_DIR);
    }
    if (!fs.existsSync(CONFIG_FILE)) {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify({ keys: {} }, null, 2), 'utf-8');
        setSecurePermissions(CONFIG_FILE);
    }
}
function readConfig() {
    ensureConfig();
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
}
function writeConfig(config) {
    ensureConfig();
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
    setSecurePermissions(CONFIG_FILE);
}
function getApiKey(provider) {
    var _a;
    const envMap = {
        gemini: 'SENTINEL_GEMINI_KEY',
        claude: 'SENTINEL_CLAUDE_KEY',
        openai: 'SENTINEL_OPENAI_KEY',
    };
    const envVar = envMap[provider];
    if (envVar && process.env[envVar])
        return process.env[envVar];
    const config = readConfig();
    if ((_a = config.keys) === null || _a === void 0 ? void 0 : _a[provider])
        return config.keys[provider];
    return '';
}
function setApiKey(provider, key) {
    const config = readConfig();
    if (!config.keys)
        config.keys = {};
    config.keys[provider] = key;
    writeConfig(config);
}
function removeApiKey(provider) {
    const config = readConfig();
    if (config.keys)
        delete config.keys[provider];
    writeConfig(config);
}
function listProviders() {
    return Object.keys(readConfig().keys || {});
}
function getConfig() {
    const config = readConfig();
    return { provider: config.provider, model: config.model };
}
function setConfig(provider, model) {
    const config = readConfig();
    config.provider = provider;
    if (model)
        config.model = model;
    writeConfig(config);
}
