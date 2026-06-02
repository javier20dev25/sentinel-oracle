/**
 * CLI 1 bridge — coordinates with Sentinel CLI v1 data.
 * Reads config, classified DB, vault, and scan history from v1.
 */
import * as fs from 'fs';
import * as path from 'path';
let cachedData = null;
function getCli1Home() {
    const home = process.env.HOME || process.env.USERPROFILE || '.';
    return path.join(home, '.sentinel');
}
export function detectCli1() {
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
export function importCli1Classified() {
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
export function formatCli1Report(data) {
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
