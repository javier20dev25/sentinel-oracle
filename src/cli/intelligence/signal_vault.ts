/**
 * Sentinel Signal Vault (v1.0)
 * 
 * Local persistence for security signals to enable temporal drift detection 
 * and historical correlation without cloud dependency.
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

export interface ScanSignal {
    repo: string;
    author: string;
    signal_type: string;
    weight: number;
    file_path: string;
    source_scan: string;
}

export class SignalVault {
    private db: Database.Database;

    constructor() {
        const dbPath = this.getDbPath();
        this.db = new Database(dbPath);
        this.initSchema();
    }

    private getDbPath(): string {
        const dir = path.join(os.homedir(), '.sentinel');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        return path.join(dir, 'vault.db');
    }

    private initSchema(): void {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                repo_name TEXT,
                pr_number INTEGER,
                author TEXT,
                risk_score REAL,
                risk_band TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                rule_name TEXT,
                severity INTEGER,
                file_path TEXT,
                line_number INTEGER,
                description TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT,
                author TEXT,
                signal_type TEXT,
                weight REAL,
                file_path TEXT,
                source_scan TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(source_scan) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_signals_author ON signals(author);
            CREATE INDEX IF NOT EXISTS idx_signals_repo ON signals(repo);
        `);
    }

    public recordScan(scan: {
        id: string;
        repo: string;
        pr: number;
        author: string;
        score: number;
        band: string;
    }): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO scans (id, repo_name, pr_number, author, risk_score, risk_band)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(scan.id, scan.repo, scan.pr, scan.author, scan.score, scan.band);
    }

    public recordSignal(signal: ScanSignal): void {
        const stmt = this.db.prepare(`
            INSERT INTO signals (repo, author, signal_type, weight, file_path, source_scan)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(signal.repo, signal.author, signal.signal_type, signal.weight, signal.file_path, signal.source_scan);
    }

    public getHistoricalSignals(author: string, daysLookback = 90): ScanSignal[] {
        const stmt = this.db.prepare(`
            SELECT * FROM signals 
            WHERE author = ? 
            AND created_at >= date('now', ?)
            ORDER BY created_at DESC
        `);
        return stmt.all(author, `-${daysLookback} days`) as ScanSignal[];
    }

    public getCorrelations(author: string, currentSignals: string[]): ScanSignal[] {
        const historical = this.getHistoricalSignals(author);
        const correlations = historical.filter(h => currentSignals.includes(h.signal_type));
        return correlations;
    }

    public purgeRepo(repoName: string): void {
        this.db.prepare('DELETE FROM signals WHERE repo = ?').run(repoName);
        this.db.prepare('DELETE FROM scans WHERE repo_name = ?').run(repoName);
    }

    public getStats(): { totalScans: number; totalSignals: number; totalFindings: number; repos: number; authors: number } {
        const count = (sql: string): number => {
            const r = this.db.prepare(sql).get() as { c: number };
            return r.c;
        };
        const scans = count('SELECT COUNT(*) as c FROM scans');
        const signals = count('SELECT COUNT(*) as c FROM signals');
        const findings = count('SELECT COUNT(*) as c FROM findings');
        const repos = count('SELECT COUNT(DISTINCT repo_name) as c FROM scans');
        const authors = count('SELECT COUNT(DISTINCT author) as c FROM signals');
        return { totalScans: scans, totalSignals: signals, totalFindings: findings, repos, authors };
    }

    /**
     * Ingest a cloud audit report from Sentinel SaaS JSON format.
     * Returns the scan ID that was created.
     */
    public ingestCloudReport(report: {
        id: string;
        repo_hash?: string;
        event_hash?: string;
        risk_score?: number;
        category?: string;
        pattern?: string;
        confidence?: number;
        metadata?: {
            github_repo_url?: string;
            pr_number?: number;
            filesScanned?: number;
            topAlerts?: Array<{
                type: string;
                _file: string;
                snippet: string;
                severity: string;
                riskLevel: number;
                description: string;
                line_number: number;
            }>;
            author?: { login: string };
        };
        created_at?: string;
    }): string {
        const scanId = report.id || report.event_hash || 'cloud_' + Date.now();
        const repoName = report.metadata?.github_repo_url || report.repo_hash || 'unknown';
        const prNumber = report.metadata?.pr_number || 0;
        const authorLogin = report.metadata?.author?.login || 'unknown';
        const riskScore = report.risk_score || 0;
        const riskBand = riskScore >= 70 ? 'CRITICAL' : (riskScore >= 40 ? 'SUSPICIOUS' : 'SAFE');

        // Persist scan record
        this.recordScan({
            id: scanId,
            repo: repoName,
            pr: prNumber,
            author: authorLogin,
            score: riskScore,
            band: riskBand
        });

        // Persist findings from topAlerts
        if (report.metadata?.topAlerts) {
            const insertFinding = this.db.prepare(`
                INSERT INTO findings (scan_id, rule_name, severity, file_path, line_number, description)
                VALUES (?, ?, ?, ?, ?, ?)
            `);
            for (const alert of report.metadata.topAlerts) {
                insertFinding.run(scanId, alert.type, alert.riskLevel || 0, alert._file || '', alert.line_number || 0, alert.description || '');
                this.recordSignal({
                    repo: repoName,
                    author: authorLogin,
                    signal_type: alert.type,
                    weight: (alert.riskLevel ?? 5) / 10,
                    file_path: alert._file || '',
                    source_scan: scanId
                });
            }
        }

        return scanId;
    }

    /**
     * Threshold-based drift detection.
     * Returns repos that have accumulated enough signals to warrant attention.
     */
    /**
     * Returns signals grouped by repo+author+type for multi-author correlation.
     */
    public getMultiAuthorSignals(): Array<{ repo: string; author: string; signal_type: string }> {
        return this.db.prepare(`
            SELECT DISTINCT s.repo, s.author, s.signal_type
            FROM signals s
            ORDER BY s.repo, s.author
        `).all() as Array<{ repo: string; author: string; signal_type: string }>;
    }

    public getThresholdAnalysis(threshold = 5): Array<{
        repo: string;
        signalCount: number;
        uniqueTypes: string[];
        riskTrend: string;
        lastSignal: string;
    }> {
        const results = this.db.prepare(`
            SELECT repo, COUNT(*) as cnt, GROUP_CONCAT(DISTINCT signal_type) as types,
                   MAX(created_at) as last_signal
            FROM signals
            GROUP BY repo
            HAVING cnt >= ?
            ORDER BY cnt DESC
        `).all(threshold) as Array<{ repo: string; cnt: number; types: string; last_signal: string }>;

        return results.map(r => {
            const types = (r.types || '').split(',');
            const criticalCount = types.filter(t =>
                t.includes('CRITICAL') || t.includes('SECRET_') || t.includes('UNSAFE_') || t === 'SHELL_PIVOT'
            ).length;
            return {
                repo: r.repo,
                signalCount: r.cnt,
                uniqueTypes: types,
                riskTrend: criticalCount > 2 ? 'ESCALATING' : (r.cnt >= threshold * 2 ? 'ELEVATED' : 'MONITOR'),
                lastSignal: r.last_signal
            };
        });
    }

    /**
     * Get historical signals for a specific repo, ordered by time.
     * Useful for temporal drift charts.
     */
    public getRepoSignalTimeline(repo: string, limit = 50): Array<{
        type: string;
        weight: number;
        file: string;
        date: string;
    }> {
        const rows = this.db.prepare(`
            SELECT signal_type, weight, file_path, created_at
            FROM signals
            WHERE repo = ?
            ORDER BY created_at DESC
            LIMIT ?
        `).all(repo, limit) as Array<{ signal_type: string; weight: number; file_path: string; created_at: string }>;

        return rows.map(r => ({
            type: r.signal_type,
            weight: r.weight,
            file: r.file_path,
            date: r.created_at
        }));
    }

    public wipe(): void {
        this.db.prepare('DELETE FROM signals').run();
        this.db.prepare('DELETE FROM findings').run();
        this.db.prepare('DELETE FROM scans').run();
    }
}
