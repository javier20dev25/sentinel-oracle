"use strict";
/**
 * CLI 1 bridge — coordinates with Sentinel CLI v1 data.
 * Reads config, classified DB, vault, and scan history from v1.
 */
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
exports.detectCli1 = detectCli1;
exports.importCli1Classified = importCli1Classified;
exports.formatCli1Report = formatCli1Report;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
let cachedData = null;
function getCli1Home() {
    const home = process.env.HOME || process.env.USERPROFILE || '.';
    return path.join(home, '.sentinel');
}
function detectCli1() {
    if (cachedData)
        return cachedData;
    const dataDir = getCli1Home();
    const configPath = path.join(dataDir, 'config.json');
    const vaultDbPath = path.join(dataDir, 'vault', 'signal_vault.db');
    const classifiedDir = path.join(dataDir, 'classified');
    const found = fs.existsSync(configPath);
    let config = {};
    let classifiedCount = 0;
    if (found) {
        try {
            config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        }
        catch (_a) {
            config = {};
        }
        if (fs.existsSync(classifiedDir)) {
            try {
                classifiedCount = fs.readdirSync(classifiedDir).filter(f => f.endsWith('.txt') || f.endsWith('.md')).length;
            }
            catch (_b) {
                classifiedCount = 0;
            }
        }
    }
    cachedData = { found, configPath, dataDir, config, classifiedCount, vaultDbPath: fs.existsSync(vaultDbPath) ? vaultDbPath : '' };
    return cachedData;
}
function importCli1Classified() {
    const data = detectCli1();
    if (!data.found)
        return { imported: 0, files: [] };
    const classifiedDir = path.join(data.dataDir, 'classified');
    if (!fs.existsSync(classifiedDir))
        return { imported: 0, files: [] };
    const files = fs.readdirSync(classifiedDir)
        .filter(f => f.endsWith('.txt') || f.endsWith('.md'))
        .slice(0, 50);
    return { imported: files.length, files };
}
function formatCli1Report(data) {
    if (!data.found) {
        return 'CLI 1 not detected on this system.';
    }
    const lines = [];
    lines.push('CLI 1 detected on this system.');
    lines.push('');
    lines.push(`Data directory: ${data.dataDir}`);
    lines.push(`Config: ${data.configPath}`);
    lines.push(`Classified files: ${data.classifiedCount}`);
    lines.push(`Vault DB: ${data.vaultDbPath || 'not found'}`);
    if (data.config.provider) {
        lines.push(`Provider: ${data.config.provider}`);
    }
    if (data.config.lastScan) {
        lines.push(`Last scan: ${data.config.lastScan}`);
    }
    if (data.classifiedCount > 0) {
        lines.push('');
        lines.push(`Tip: Use /cli1-import to import classified files into Oracle.`);
    }
    return lines.join('\n');
}
