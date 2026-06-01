/**
 * Sentinel System Auditor (v2.0)
 * 
 * The 'doctor' command.
 * Scans local node_modules using real LiteScanner for actual threat detection.
 */

import * as fs from 'fs';
import * as path from 'path';
import { LiteScanner } from '../../core/lite/lite_scanner';
import * as pc from 'picocolors';

export class SystemAuditor {
    private scanner: LiteScanner;

    constructor() {
        this.scanner = new LiteScanner();
    }

    public async runDoctor(deep = false) {
        console.log(pc.magenta('\n🩺 SENTINEL SYSTEM HEALTH REPORT'));
        console.log(pc.dim('   Scanning local workspace...\n'));

        const results: {
            packages: number;
            critical: number;
            suspicious: number;
            findings: Array<{ name: string; file: string; line: number; severity: string; type: string; description: string; snippet: string }>;
        } = { packages: 0, critical: 0, suspicious: 0, findings: [] };

        const pkgJsonPath = path.join(process.cwd(), 'package.json');
        if (!fs.existsSync(pkgJsonPath)) {
            console.log(pc.yellow('No package.json found.'));
            return;
        }

        const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        results.packages = Object.keys(deps).length;
        console.log(pc.cyan(`📦 Found ${results.packages} Node.js dependencies.`));

        const nodeModules = path.join(process.cwd(), 'node_modules');
        if (!fs.existsSync(nodeModules)) {
            console.log(pc.yellow('node_modules not found. Run npm install first.'));
            return;
        }

        // Always scan package.json for config-level threats
        const pkgContent = fs.readFileSync(pkgJsonPath, 'utf8');
        const pkgPatch = `@@ -0,0 +1,1 @@\n+${pkgContent.split('\n').join('\n+')}`;
        const pkgFindings = this.scanner.scanPatch('package.json', pkgPatch);
        for (const f of pkgFindings) {
            results.findings.push({ name: 'package.json', ...f });
            if (f.severity === 'CRITICAL') results.critical++;
            else if (f.severity === 'HIGH' || f.severity === 'MEDIUM') results.suspicious++;
        }

        if (deep) {
            console.log(pc.dim('   Deep scan: auditing installed packages...\n'));

            const depNames = Object.keys(deps).sort((a, b) => a.localeCompare(b));
            for (const depName of depNames) {
                const pkgPath = path.join(nodeModules, depName);
                if (!fs.existsSync(pkgPath)) continue;

                // Walk the package directory (max 2 levels, avoid huge scans)
                const files: string[] = [];
                try {
                    const items = fs.readdirSync(pkgPath);
                    for (const item of items) {
                        if (item.startsWith('.') || item === 'node_modules') continue;
                        const full = path.join(pkgPath, item);
                        if (fs.statSync(full).isDirectory()) {
                            const subItems = fs.readdirSync(full);
                            for (const sub of subItems) {
                                if (sub.endsWith('.js') || sub.endsWith('.mjs')) {
                                    files.push(path.join(full, sub));
                                }
                            }
                        } else if (item.endsWith('.js') || item.endsWith('.mjs')) {
                            files.push(full);
                        }
                    }
                } catch (_unused: unknown) { /* skip permission errors */ }

                for (const file of files.slice(0, 20)) { // Max 20 files/pkg for perf
                    try {
                        const content = fs.readFileSync(file, 'utf8');
                        const rel = path.relative(nodeModules, file);
                        const patch = `@@ -0,0 +1,1 @@\n+${content.split('\n').join('\n+')}`;
                        const fnds = this.scanner.scanPatch(rel, patch);
                        for (const f of fnds) {
                            results.findings.push({ name: depName, ...f });
                            if (f.severity === 'CRITICAL') results.critical++;
                            else if (f.severity === 'HIGH' || f.severity === 'MEDIUM') results.suspicious++;
                        }
                    } catch (_unused2: unknown) {}
                }
            }
        }

        this.reportResults(results);
    }

    private reportResults(results: {
        packages: number; critical: number; suspicious: number;
        findings: Array<{ name: string; file: string; line: number; severity: string; type: string; description: string; snippet: string }>;
    }) {
        console.log(pc.dim('━━━━━━━━━━━━━━━━━━━━━'));

        if (results.findings.length === 0) {
            console.log(pc.green('\n✔ Your system appears healthy. No threats found.'));
        } else {
            // Group by package
            const grouped = new Map<string, typeof results.findings>();
            for (const f of results.findings) {
                const key = f.name;
                if (!grouped.has(key)) grouped.set(key, []);
                grouped.get(key)!.push(f);
            }

            for (const [name, fnds] of grouped) {
                const worst = fnds.reduce((w: typeof results.findings[0], f: typeof results.findings[0]) =>
                    f.severity === 'CRITICAL' ? f : (w.severity === 'CRITICAL' ? w : f)
                );
                const color = worst.severity === 'CRITICAL' ? pc.bgRed : (worst.severity === 'HIGH' ? pc.bgYellow : pc.bgCyan);
                console.log(`\n ${color(pc.black(` ${worst.severity} `))} ${pc.bold(name)} (${fnds.length} finding(s))`);
                for (const f of fnds.slice(0, 3)) {
                    console.log(pc.dim(`    ${f.file}:${f.line} → ${f.type}: ${f.description.substring(0, 80)}`));
                }
                if (fnds.length > 3) console.log(pc.dim(`    ... and ${fnds.length - 3} more`));
            }
        }

        console.log(pc.dim('\n━━━━━━━━━━━━━━━━━━━━━'));
        const posture = results.critical > 0 ? pc.red('HIGH RISK') : (results.suspicious > 0 ? pc.yellow('MODERATE RISK') : pc.green('SAFE'));
        console.log(`System posture: ${posture}\n`);
    }
}
