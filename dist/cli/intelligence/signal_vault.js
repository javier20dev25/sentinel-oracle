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
export class SignalVault {
    constructor() {
        const dbPath = this.getDbPath();
        this.db = new Database(dbPath);
        this.initSchema();
    }
    getDbPath() {
        const dir = path.join(os.homedir(), '.sentinel');
        if (!fs.existsSync(dir))
            fs.mkdirSync(dir, { recursive: true });
        return path.join(dir, 'vault.db');
    }
    initSchema() {
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
    recordScan(scan) {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO scans (id, repo_name, pr_number, author, risk_score, risk_band)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(scan.id, scan.repo, scan.pr, scan.author, scan.score, scan.band);
    }
    recordSignal(signal) {
        const stmt = this.db.prepare(`
            INSERT INTO signals (repo, author, signal_type, weight, file_path, source_scan)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(signal.repo, signal.author, signal.signal_type, signal.weight, signal.file_path, signal.source_scan);
    }
    getHistoricalSignals(author, daysLookback = 90) {
        const stmt = this.db.prepare(`
            SELECT * FROM signals 
            WHERE author = ? 
            AND created_at >= date('now', ?)
            ORDER BY created_at DESC
        `);
        return stmt.all(author, `-${daysLookback} days`);
    }
    getCorrelations(author, currentSignals) {
        const historical = this.getHistoricalSignals(author);
        const correlations = historical.filter(h => currentSignals.includes(h.signal_type));
        return correlations;
    }
    purgeRepo(repoName) {
        this.db.prepare('DELETE FROM signals WHERE repo = ?').run(repoName);
        this.db.prepare('DELETE FROM scans WHERE repo_name = ?').run(repoName);
    }
    getStats() {
        const count = (sql) => {
            const r = this.db.prepare(sql).get();
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
    ingestCloudReport(report) {
        var _a, _b, _c, _d, _e, _f;
        const scanId = report.id || report.event_hash || 'cloud_' + Date.now();
        const repoName = ((_a = report.metadata) === null || _a === void 0 ? void 0 : _a.github_repo_url) || report.repo_hash || 'unknown';
        const prNumber = ((_b = report.metadata) === null || _b === void 0 ? void 0 : _b.pr_number) || 0;
        const authorLogin = ((_d = (_c = report.metadata) === null || _c === void 0 ? void 0 : _c.author) === null || _d === void 0 ? void 0 : _d.login) || 'unknown';
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
        if ((_e = report.metadata) === null || _e === void 0 ? void 0 : _e.topAlerts) {
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
                    weight: ((_f = alert.riskLevel) !== null && _f !== void 0 ? _f : 5) / 10,
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
    getMultiAuthorSignals() {
        return this.db.prepare(`
            SELECT DISTINCT s.repo, s.author, s.signal_type
            FROM signals s
            ORDER BY s.repo, s.author
        `).all();
    }
    getThresholdAnalysis(threshold = 5) {
        const results = this.db.prepare(`
            SELECT repo, COUNT(*) as cnt, GROUP_CONCAT(DISTINCT signal_type) as types,
                   MAX(created_at) as last_signal
            FROM signals
            GROUP BY repo
            HAVING cnt >= ?
            ORDER BY cnt DESC
        `).all(threshold);
        return results.map(r => {
            const types = (r.types || '').split(',');
            const criticalCount = types.filter(t => t.includes('CRITICAL') || t.includes('SECRET_') || t.includes('UNSAFE_') || t === 'SHELL_PIVOT').length;
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
    getRepoSignalTimeline(repo, limit = 50) {
        const rows = this.db.prepare(`
            SELECT signal_type, weight, file_path, created_at
            FROM signals
            WHERE repo = ?
            ORDER BY created_at DESC
            LIMIT ?
        `).all(repo, limit);
        return rows.map(r => ({
            type: r.signal_type,
            weight: r.weight,
            file: r.file_path,
            date: r.created_at
        }));
    }
    wipe() {
        this.db.prepare('DELETE FROM signals').run();
        this.db.prepare('DELETE FROM findings').run();
        this.db.prepare('DELETE FROM scans').run();
    }
}
