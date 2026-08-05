import Database from 'better-sqlite3';
import * as path from 'path';
import { encrypt, decrypt } from './encryption';
import type { CIPolicy, CapabilitySnapshot } from '../scanner/intel/types';

export interface PendingPR {
    id: number;
    prNumber: number;
    owner: string;
    repo: string;
    title: string;
    author: string;
    sha: string;
    ciStatus: string;
    sentinelStatus: string;
    authStatus: 'pending' | 'authorized' | 'rejected' | 'expired';
    createdAt: number;
    authorizedAt: number | null;
    deviceName: string | null;
    checkRunId: number | null;
}

export interface AuthDevice {
    id: number;
    name: string;
    credentialId: string;
    publicKey: string;
    counter: number;
    transports: string;
    createdAt: number;
    lastUsedAt: number | null;
}

export interface Session {
    id: string
    credentialId: string
    deviceName: string
    createdAt: number
    expiresAt: number
    lastUsedAt: number
    csrfToken?: string
    userAgent?: string
}

export interface AuditEntry {
    id: number;
    timestamp: number;
    action: string;
    prNumber: number | null;
    detail: string;
}

export interface TokenInventory {
  id: number
  tokenType: 'github_pat' | 'github_app' | 'github_oauth' | 'generic' | 'found_secret'
  name: string
  source: 'github_api' | 'repo_scan' | 'manual'
  scopes: string | null
  fingerprint: string
  firstSeenAt: number
  lastSeenAt: number | null
  expiresAt: number | null
  lastRotation: number | null
  riskScore: string
  notes: string | null
  metadata: string | null
}

export interface TokenStats {
  total: number
  highRisk: number
  expiringSoon: number
  expired: number
}

export interface ScanResultRow {
  prNumber: number
  scanHash: string
  riskScore: number
  critical: number
  high: number
  medium: number
  low: number
  findingsJson: string
  scannedAt: number
  intelJson?: string
  buildIntelJson?: string
  state?: string
  stateReasonsJson?: string
  attestationJson?: string
}

export interface SavedExplanationRow {
  prNumber: number
  type: 'pr' | 'scan'
  summaryJson: string
  argumentation: string
  savedAt: number
}

export interface BlacklistPRRow {
  prNumber: number
  owner: string
  repo: string
  title: string
  author: string
  sha: string
  reason: string
  savedAt: number
}

export interface AIAnalysisRow {
  prNumber: number
  scanHash: string
  analysisJson: string
  reviewPriority: string
  impactLevel: string
  complexity: string
  injectionDetected: number
  injectionAttemptsJson: string
  analyzedAt: number
}

export class DatabaseStore {
    private db: Database.Database;
    private encryptionKey: Buffer;
    private idleTimeoutMs: number;

    constructor(dataDir: string, encryptionKey?: Buffer, idleTimeoutMs = 1800000) {
        this.db = new Database(path.join(dataDir, 'oracle.db'));
        this.db.pragma('journal_mode = WAL');
        this.encryptionKey = encryptionKey || Buffer.alloc(0);
        this.idleTimeoutMs = idleTimeoutMs;
        this.migrate();
    }

    private runMigration(sql: string): void {
      try {
        this.db.prepare(sql).run()
      } catch (err: any) {
        const msg = err instanceof Error ? err.message : String(err)
        if (msg.includes('duplicate column name') || msg.includes('duplicate column')) {
          return
        }
        console.error(`[db] Migration warning: ${sql} — ${msg}`)
      }
    }

    private migrate(): void {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS pending_prs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_number INTEGER NOT NULL UNIQUE,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                sha TEXT NOT NULL,
                ci_status TEXT NOT NULL DEFAULT 'unknown',
                sentinel_status TEXT NOT NULL DEFAULT 'unknown',
                auth_status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                authorized_at INTEGER,
                device_name TEXT
            );
            CREATE TABLE IF NOT EXISTS auth_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                counter INTEGER NOT NULL DEFAULT 0,
                transports TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL,
                last_used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                pr_number INTEGER NOT NULL,
                type TEXT NOT NULL DEFAULT 'authorization',
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                action TEXT NOT NULL,
                pr_number INTEGER,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        `);
        this.runMigration('ALTER TABLE pending_prs ADD COLUMN device_name TEXT')
        this.runMigration('ALTER TABLE pending_prs ADD COLUMN check_run_id INTEGER')
        this.runMigration('ALTER TABLE sessions ADD COLUMN csrf_token TEXT DEFAULT \'\'')
        this.runMigration('ALTER TABLE sessions ADD COLUMN user_agent TEXT DEFAULT \'\'')
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS token_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT NOT NULL,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                scopes TEXT,
                fingerprint TEXT NOT NULL UNIQUE,
                first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER,
                expires_at INTEGER,
                last_rotation INTEGER,
                risk_score TEXT DEFAULT 'unknown',
                notes TEXT,
                metadata TEXT
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS pr_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_number INTEGER NOT NULL,
                filename TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'modified',
                additions INTEGER DEFAULT 0,
                deletions INTEGER DEFAULT 0,
                size_bytes INTEGER DEFAULT 0,
                scanned_at INTEGER NOT NULL,
                auth_status TEXT NOT NULL DEFAULT 'pending'
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS workflow_times (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha TEXT NOT NULL,
                pr_number INTEGER,
                check_name TEXT NOT NULL,
                duration_ms INTEGER,
                scanned_at INTEGER NOT NULL,
                UNIQUE(filename, sha, check_name)
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS workflow_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha TEXT NOT NULL,
                pr_number INTEGER,
                job_name TEXT NOT NULL,
                step_name TEXT NOT NULL,
                step_number INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0,
                status TEXT DEFAULT '',
                scanned_at INTEGER NOT NULL
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS workflow_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pr_number INTEGER NOT NULL,
                sha TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                job_structure_json TEXT NOT NULL,
                scanned_at INTEGER NOT NULL,
                UNIQUE(pr_number, sha)
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS ci_policy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL DEFAULT 'default',
                policy_json TEXT NOT NULL DEFAULT '{}',
                updated_at INTEGER NOT NULL,
                UNIQUE(repo)
            );
        `)
        this.db.exec(`
            CREATE INDEX IF NOT EXISTS idx_pr_files_pr ON pr_files(pr_number);
            CREATE INDEX IF NOT EXISTS idx_pr_files_filename ON pr_files(filename);
            CREATE INDEX IF NOT EXISTS idx_pr_files_auth ON pr_files(auth_status);
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scan_results (
                pr_number INTEGER NOT NULL,
                scan_hash TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                critical INTEGER DEFAULT 0,
                high INTEGER DEFAULT 0,
                medium INTEGER DEFAULT 0,
                low INTEGER DEFAULT 0,
                findings_json TEXT NOT NULL,
                scanned_at INTEGER NOT NULL,
                UNIQUE(pr_number, scan_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_results_pr ON scan_results(pr_number);
        `)
        this.runMigration("ALTER TABLE scan_results ADD COLUMN intel_json TEXT DEFAULT ''")
        this.runMigration("ALTER TABLE scan_results ADD COLUMN build_intel_json TEXT DEFAULT ''")
        this.runMigration("ALTER TABLE scan_results ADD COLUMN state TEXT NOT NULL DEFAULT 'PASS'")
        this.runMigration("ALTER TABLE scan_results ADD COLUMN state_reasons_json TEXT DEFAULT ''")
        this.runMigration("ALTER TABLE scan_results ADD COLUMN attestation_json TEXT DEFAULT ''")
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS ai_analysis (
                pr_number INTEGER NOT NULL,
                scan_hash TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                review_priority TEXT NOT NULL DEFAULT 'low',
                impact_level TEXT NOT NULL DEFAULT 'low',
                complexity TEXT NOT NULL DEFAULT 'low',
                injection_detected INTEGER NOT NULL DEFAULT 0,
                injection_attempts_json TEXT NOT NULL DEFAULT '[]',
                analyzed_at INTEGER NOT NULL,
                UNIQUE(pr_number, scan_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_ai_analysis_pr ON ai_analysis(pr_number);
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS capability_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_repo ON capability_snapshots(owner, repo, created_at);
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS saved_explanations (
                pr_number INTEGER NOT NULL,
                type TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                argumentation TEXT NOT NULL,
                saved_at INTEGER NOT NULL,
                UNIQUE(pr_number, type)
            );
        `)
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS blacklist_prs (
                pr_number INTEGER PRIMARY KEY,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                sha TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                saved_at INTEGER NOT NULL
            );
        `)
    }

    upsertPR(pr: Omit<PendingPR, 'id'>): void {
        this.db.prepare(`
            INSERT INTO pending_prs (pr_number, owner, repo, title, author, sha, ci_status, sentinel_status, auth_status, created_at, authorized_at, device_name, check_run_id)
            VALUES (@prNumber, @owner, @repo, @title, @author, @sha, @ciStatus, @sentinelStatus, @authStatus, @createdAt, @authorizedAt, @deviceName, @checkRunId)
            ON CONFLICT(pr_number) DO UPDATE SET
                sha = excluded.sha,
                ci_status = excluded.ci_status,
                sentinel_status = excluded.sentinel_status,
                auth_status = excluded.auth_status,
                title = excluded.title,
                device_name = excluded.device_name,
                check_run_id = excluded.check_run_id
        `).run(pr);
    }

    private mapPR(row: any): PendingPR {
        return {
            id: row.id,
            prNumber: row.pr_number,
            owner: row.owner,
            repo: row.repo,
            title: row.title,
            author: row.author,
            sha: row.sha,
            ciStatus: row.ci_status,
            sentinelStatus: row.sentinel_status,
            authStatus: row.auth_status,
            createdAt: row.created_at,
            authorizedAt: row.authorized_at,
            deviceName: row.device_name || null,
            checkRunId: row.check_run_id || null,
        }
    }

    getPendingPRs(): PendingPR[] {
        const rows = this.db.prepare(
            'SELECT * FROM pending_prs WHERE auth_status = ? ORDER BY created_at DESC'
        ).all('pending')
        return rows.map(r => this.mapPR(r))
    }

    getCompletedPRs(): PendingPR[] {
        const rows = this.db.prepare(
            "SELECT * FROM pending_prs WHERE auth_status IN ('authorized','rejected','expired') ORDER BY authorized_at DESC"
        ).all()
        return rows.map(r => this.mapPR(r))
    }

    getPRByNumber(prNumber: number): PendingPR | undefined {
        const row = this.db.prepare(
            'SELECT * FROM pending_prs WHERE pr_number = ?'
        ).get(prNumber)
        return row ? this.mapPR(row) : undefined
    }

    setAuthStatus(prNumber: number, status: PendingPR['authStatus'], deviceName?: string): void {
        this.db.prepare(
            'UPDATE pending_prs SET auth_status = ?, authorized_at = ?, device_name = ? WHERE pr_number = ?'
        ).run(status, status === 'authorized' ? Date.now() : null, deviceName || null, prNumber);
        if (status === 'authorized' || status === 'rejected') {
            this.updatePRFilesAuthStatus(prNumber, status)
        }
    }

    setCheckRunId(prNumber: number, checkRunId: number): void {
        this.db.prepare(
            'UPDATE pending_prs SET check_run_id = ? WHERE pr_number = ?'
        ).run(checkRunId, prNumber);
    }

    storePRFiles(prNumber: number, files: { filename: string; status: string; additions: number; deletions: number; patch?: string }[], authStatus = 'pending'): void {
        const now = Date.now()
        const del = this.db.prepare('DELETE FROM pr_files WHERE pr_number = ?')
        const ins = this.db.prepare('INSERT INTO pr_files (pr_number, filename, status, additions, deletions, size_bytes, scanned_at, auth_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        const tx = this.db.transaction(() => {
            del.run(prNumber)
            for (const f of files) {
                const sizeBytes = f.patch ? Buffer.byteLength(f.patch, 'utf-8') : 0
                ins.run(prNumber, f.filename, f.status, f.additions, f.deletions, sizeBytes, now, authStatus)
            }
        })
        tx()
    }

    getPRFiles(prNumber: number): { filename: string; status: string; additions: number; deletions: number; sizeBytes: number; scannedAt: number }[] {
        return this.db.prepare('SELECT filename, status, additions, deletions, size_bytes as sizeBytes, scanned_at as scannedAt FROM pr_files WHERE pr_number = ? ORDER BY filename').all(prNumber) as any
    }

    getFileHistory(filename: string, limit = 100): { prNumber: number; additions: number; deletions: number; sizeBytes: number; scannedAt: number }[] {
        return this.db.prepare(`
            SELECT f.pr_number, f.additions, f.deletions, f.size_bytes as sizeBytes, f.scanned_at as scannedAt
            FROM pr_files f
            WHERE f.filename = ?
            ORDER BY f.scanned_at ASC
            LIMIT ?
        `).all(filename, limit) as any
    }

    storeWorkflowTimes(filename: string, entries: { sha: string; prNumber: number; checkName: string; durationMs: number }[]): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO workflow_times (filename, sha, pr_number, check_name, duration_ms, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `)
        const now = Date.now()
        for (const e of entries) {
            stmt.run(filename, e.sha, e.prNumber, e.checkName, e.durationMs, now)
        }
    }

    getWorkflowHistory(filename: string): { sha: string; prNumber: number; checkName: string; durationMs: number; scannedAt: number }[] {
        return this.db.prepare(`
            SELECT sha, pr_number as prNumber, check_name as checkName, duration_ms as durationMs, scanned_at as scannedAt
            FROM workflow_times
            WHERE filename = ?
            ORDER BY scanned_at ASC
        `).all(filename) as any
    }

    getAllWorkflowRecords(): { checkName: string; durationMs: number; prNumber: number; scannedAt: number; filename: string }[] {
        return this.db.prepare(`
            SELECT check_name as checkName, duration_ms as durationMs, pr_number as prNumber, scanned_at as scannedAt, filename
            FROM workflow_times
            ORDER BY scanned_at ASC
        `).all() as any
    }

    storeWorkflowTelemetry(entries: { checkName: string; durationMs: number; prNumber: number; filename: string }[]): void {
        const stmt = this.db.prepare(`
            INSERT OR REPLACE INTO workflow_times (filename, sha, pr_number, check_name, duration_ms, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `)
        const now = Date.now()
        for (const e of entries) {
            stmt.run(e.filename, `${now}`, e.prNumber, e.checkName, e.durationMs, now)
        }
    }

    // === Step-level telemetry ===
    storeWorkflowSteps(entries: { filename: string; sha: string; prNumber: number; jobName: string; stepName: string; stepNumber: number; durationMs: number; status: string }[]): void {
        const stmt = this.db.prepare(`
            INSERT INTO workflow_steps (filename, sha, pr_number, job_name, step_name, step_number, duration_ms, status, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        const now = Date.now()
        const tx = this.db.transaction(() => {
            for (const e of entries) {
                stmt.run(e.filename, e.sha, e.prNumber, e.jobName, e.stepName, e.stepNumber, e.durationMs, e.status, now)
            }
        })
        tx()
    }

    getWorkflowSteps(filenames?: string[], sinceMs?: number): { filename: string; sha: string; prNumber: number; jobName: string; stepName: string; stepNumber: number; durationMs: number; status: string; scannedAt: number }[] {
        let sql = 'SELECT filename, sha, pr_number as prNumber, job_name as jobName, step_name as stepName, step_number as stepNumber, duration_ms as durationMs, status, scanned_at as scannedAt FROM workflow_steps'
        const params: any[] = []
        const wheres: string[] = []
        if (filenames && filenames.length > 0) {
            wheres.push(`filename IN (${filenames.map(() => '?').join(',')})`)
            params.push(...filenames)
        }
        if (sinceMs) {
            wheres.push('scanned_at >= ?')
            params.push(sinceMs)
        }
        if (wheres.length > 0) sql += ' WHERE ' + wheres.join(' AND ')
        sql += ' ORDER BY scanned_at ASC'
        return this.db.prepare(sql).all(...params) as any
    }

    // === Execution fingerprints ===
    storeFingerprint(prNumber: number, sha: string, hash: string, jobStructure: any): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO workflow_fingerprints (pr_number, sha, fingerprint_hash, job_structure_json, scanned_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(prNumber, sha, hash, JSON.stringify(jobStructure), Date.now())
    }

    getFingerprint(prNumber: number): { sha: string; hash: string; jobStructure: any; scannedAt: number } | undefined {
        return this.db.prepare(`
            SELECT sha, fingerprint_hash as hash, job_structure_json as jobStructure, scanned_at as scannedAt
            FROM workflow_fingerprints
            WHERE pr_number = ?
            ORDER BY scanned_at DESC
            LIMIT 1
        `).get(prNumber) as any
    }

    getAllFingerprints(): { prNumber: number; sha: string; hash: string; scannedAt: number }[] {
        return this.db.prepare(`
            SELECT pr_number as prNumber, sha, fingerprint_hash as hash, scanned_at as scannedAt
            FROM workflow_fingerprints
            ORDER BY scanned_at DESC
        `).all() as any
    }

    // === CI Policy ===
    getPolicy(repo = 'default'): CIPolicy | null {
        const row = this.db.prepare('SELECT policy_json FROM ci_policy WHERE repo = ?').get(repo) as any
        if (!row) return null
        try { return JSON.parse(row.policy_json) } catch { return null }
    }

    setPolicy(repo: string, policy: CIPolicy): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO ci_policy (repo, policy_json, updated_at)
            VALUES (?, ?, ?)
        `).run(repo, JSON.stringify(policy), Date.now())
    }

    getRepoFileAverages(): { filename: string; avgAdditions: number; avgDeletions: number; avgSizeBytes: number; count: number }[] {
        return this.db.prepare(`
            SELECT filename,
                   ROUND(AVG(additions)) as avgAdditions,
                   ROUND(AVG(deletions)) as avgDeletions,
                   ROUND(AVG(size_bytes)) as avgSizeBytes,
                   COUNT(*) as count
            FROM pr_files
            WHERE auth_status IN ('authorized','rejected')
            GROUP BY filename
            HAVING count > 0
        `).all() as any
    }

    updatePRFilesAuthStatus(prNumber: number, authStatus: string): void {
        this.db.prepare('UPDATE pr_files SET auth_status = ? WHERE pr_number = ?').run(authStatus, prNumber)
    }

    getBackfillCheckpoint(): number {
        const row = this.db.prepare("SELECT value FROM config WHERE key = 'backfill_checkpoint'").get() as any
        return row ? parseInt(row.value, 10) || 0 : 0
    }

    setBackfillCheckpoint(prNumber: number): void {
        this.db.prepare("INSERT INTO config (key, value) VALUES ('backfill_checkpoint', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(prNumber))
    }

    registerDevice(device: Omit<AuthDevice, 'id' | 'createdAt' | 'lastUsedAt'>): void {
        const stored = this.encryptionKey.length > 0
            ? { ...device, publicKey: encrypt(device.publicKey, this.encryptionKey) }
            : device
        this.db.prepare(`
            INSERT INTO auth_devices (name, credential_id, public_key, counter, transports, created_at)
            VALUES (@name, @credentialId, @publicKey, @counter, @transports, @createdAt)
        `).run({ ...stored, createdAt: Date.now() });
    }

    private mapDevice(row: any): AuthDevice {
        return {
            id: row.id,
            name: row.name,
            credentialId: row.credential_id,
            publicKey: row.public_key,
            counter: row.counter,
            transports: row.transports,
            createdAt: row.created_at,
            lastUsedAt: row.last_used_at,
        }
    }

    getDeviceByCredentialId(credentialId: string): AuthDevice | undefined {
        const row = this.db.prepare(
            'SELECT * FROM auth_devices WHERE credential_id = ?'
        ).get(credentialId)
        if (!row) return undefined
        const device = this.mapDevice(row)
        if (this.encryptionKey.length > 0) {
            try {
                device.publicKey = decrypt(device.publicKey, this.encryptionKey)
            } catch {
                return undefined
            }
        }
        return device
    }

    listDevices(): AuthDevice[] {
        const rows = this.db.prepare(
            'SELECT * FROM auth_devices ORDER BY created_at DESC'
        ).all()
        return rows.map(r => {
            const d = this.mapDevice(r)
            if (this.encryptionKey.length > 0) {
                try { d.publicKey = decrypt(d.publicKey, this.encryptionKey) } catch { d.publicKey = '' }
            }
            return d
        })
    }

    deleteDevice(credentialId: string): void {
      this.db.prepare('DELETE FROM auth_devices WHERE credential_id = ?').run(credentialId)
    }

    updateDeviceCounter(credentialId: string, counter: number): void {
        this.db.prepare(
            'UPDATE auth_devices SET counter = ?, last_used_at = ? WHERE credential_id = ?'
        ).run(counter, Date.now(), credentialId);
    }

    storeChallenge(id: string, prNumber: number, data: string, expiresAt: number): void {
        const stored = this.encryptionKey.length > 0 ? encrypt(data, this.encryptionKey) : data
        this.db.prepare(`
            INSERT INTO challenges (id, pr_number, type, data, expires_at, used, created_at)
            VALUES (?, ?, 'authorization', ?, ?, 0, ?)
        `).run(id, prNumber, stored, expiresAt, Date.now());
    }

    consumeChallenge(id: string): { prNumber: number; data: string } | null {
        const row = this.db.prepare(
            'SELECT id, pr_number, data, expires_at, used FROM challenges WHERE id = ?'
        ).get(id) as { id: string; pr_number: number; data: string; expires_at: number; used: number } | undefined;

        if (!row || row.used !== 0 || Date.now() > row.expires_at) return null;

        const result = this.db.prepare('UPDATE challenges SET used = 1 WHERE id = ? AND used = 0').run(id);
        if (result.changes === 0) return null;

        const data = this.encryptionKey.length > 0 ? decrypt(row.data, this.encryptionKey) : row.data
        return { prNumber: row.pr_number, data };
    }

    getChallenge(id: string): { prNumber: number; data: string; used: number } | null {
        const row = this.db.prepare(
            'SELECT pr_number, data, used FROM challenges WHERE id = ?'
        ).get(id) as { pr_number: number; data: string; used: number } | undefined;
        if (!row) return null;
        const data = this.encryptionKey.length > 0 ? decrypt(row.data, this.encryptionKey) : row.data
        return { prNumber: row.pr_number, data, used: row.used };
    }

    createSession(credentialId: string, deviceName: string, ttlMs: number, csrfToken?: string, userAgent?: string): string {
        const { v4: uuidv4 } = require('uuid')
        const id = uuidv4()
        const now = Date.now()
        const token = csrfToken || require('crypto').randomBytes(32).toString('hex')
        this.db.prepare(`
            INSERT INTO sessions (id, credential_id, device_name, created_at, expires_at, last_used_at, csrf_token, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(id, credentialId, deviceName, now, now + ttlMs, now, token, userAgent || '')
        return id
    }

    getSession(id: string): Session | undefined {
        const row = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as any
        if (!row) return undefined
        if (Date.now() > row.expires_at || Date.now() - row.last_used_at > this.idleTimeoutMs) {
            this.db.prepare('DELETE FROM sessions WHERE id = ?').run(id)
            return undefined
        }
        return {
            id: row.id,
            credentialId: row.credential_id,
            deviceName: row.device_name,
            createdAt: row.created_at,
            expiresAt: row.expires_at,
            lastUsedAt: row.last_used_at,
            csrfToken: row.csrf_token || undefined,
            userAgent: row.user_agent || undefined,
        }
    }

    touchSession(id: string): void {
        this.db.prepare('UPDATE sessions SET last_used_at = ? WHERE id = ?').run(Date.now(), id)
    }

    deleteSession(id: string): void {
        this.db.prepare('DELETE FROM sessions WHERE id = ?').run(id)
    }

    deleteSessionsByCredentialId(credentialId: string): void {
        this.db.prepare('DELETE FROM sessions WHERE credential_id = ?').run(credentialId)
    }

    getSessionCSRFToken(sessionId: string): string | null {
        const row = this.db.prepare('SELECT csrf_token FROM sessions WHERE id = ?').get(sessionId) as any
        return row ? row.csrf_token : null
    }

    pruneExpiredSessions(): number {
        const result = this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now())
        return result.changes
    }

    pruneExpiredWebAuthnChallenges(ttlMs: number): number {
        const keys = this.db.prepare(
            "SELECT key, value FROM config WHERE key LIKE 'webauthn_challenge_%' OR key LIKE 'webauthn_assertion_%'"
        ).all() as { key: string; value: string }[]
        const now = Date.now()
        let removed = 0
        for (const row of keys) {
            if (!row.value) {
                this.db.prepare('DELETE FROM config WHERE key = ?').run(row.key)
                removed++
                continue
            }
            try {
                const data = JSON.parse(row.value)
                const createdAt = data.createdAt || 0
                if (now - createdAt > ttlMs) {
                    this.db.prepare('DELETE FROM config WHERE key = ?').run(row.key)
                    removed++
                }
            } catch {
                this.log('cleanup', null, `Deleting malformed WebAuthn entry: ${row.key}`)
                this.db.prepare('DELETE FROM config WHERE key = ?').run(row.key)
                removed++
            }
        }
        return removed
    }

    log(action: string, prNumber: number | null, detail: string): void {
        this.db.prepare(
            'INSERT INTO audit_log (timestamp, action, pr_number, detail) VALUES (?, ?, ?, ?)'
        ).run(Date.now(), action, prNumber, detail);
    }

    private mapAudit(row: any): AuditEntry {
        return {
            id: row.id,
            timestamp: row.timestamp,
            action: row.action,
            prNumber: row.pr_number,
            detail: row.detail,
        }
    }

    getAuditLog(limit = 100): AuditEntry[] {
        const rows = this.db.prepare(
            'SELECT * FROM audit_log ORDER BY id DESC LIMIT ?'
        ).all(limit)
        return rows.map(r => this.mapAudit(r))
    }

    storeCapabilitySnapshot(owner: string, repo: string, prNumber: number, snapshot: CapabilitySnapshot): void {
        this.db.prepare(`
            INSERT INTO capability_snapshots (owner, repo, pr_number, snapshot_json, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(owner, repo, prNumber, JSON.stringify(snapshot), Date.now())
    }

    getCapabilitySnapshots(owner: string, repo: string, limit = 90): { snapshot: CapabilitySnapshot; createdAt: number; prNumber: number }[] {
        const rows = this.db.prepare(`
            SELECT snapshot_json as snapshotJson, created_at as createdAt, pr_number as prNumber
            FROM capability_snapshots
            WHERE owner = ? AND repo = ?
            ORDER BY created_at ASC
            LIMIT ?
        `).all(owner, repo, limit) as any[]
        return rows.map(r => ({
            snapshot: JSON.parse(r.snapshotJson) as CapabilitySnapshot,
            createdAt: r.createdAt,
            prNumber: r.prNumber,
        }))
    }

    getLatestSnapshot(owner: string, repo: string): { snapshot: CapabilitySnapshot; createdAt: number; prNumber: number } | undefined {
        const row = this.db.prepare(`
            SELECT snapshot_json as snapshotJson, created_at as createdAt, pr_number as prNumber
            FROM capability_snapshots
            WHERE owner = ? AND repo = ?
            ORDER BY created_at DESC LIMIT 1
        `).get(owner, repo) as any
        if (!row) return undefined
        return {
            snapshot: JSON.parse(row.snapshotJson),
            createdAt: row.createdAt,
            prNumber: row.prNumber,
        }
    }

    getConfig(key: string): string | undefined {
        const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get(key) as { value: string } | undefined;
        return row?.value;
    }

    setConfig(key: string, value: string): void {
        this.db.prepare(
            'INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
        ).run(key, value);
    }

    addToken(token: Omit<TokenInventory, 'id'>): void {
        this.db.prepare(`
            INSERT INTO token_inventory (token_type, name, source, scopes, fingerprint, first_seen_at, last_seen_at, expires_at, last_rotation, risk_score, notes, metadata)
            VALUES (@tokenType, @name, @source, @scopes, @fingerprint, @firstSeenAt, @lastSeenAt, @expiresAt, @lastRotation, @riskScore, @notes, @metadata)
        `).run(token)
    }

    getAllTokens(): TokenInventory[] {
        const rows = this.db.prepare('SELECT * FROM token_inventory ORDER BY first_seen_at DESC').all()
        return rows.map(r => ({
            id: (r as any).id,
            tokenType: (r as any).token_type,
            name: (r as any).name,
            source: (r as any).source,
            scopes: (r as any).scopes,
            fingerprint: (r as any).fingerprint,
            firstSeenAt: (r as any).first_seen_at,
            lastSeenAt: (r as any).last_seen_at,
            expiresAt: (r as any).expires_at,
            lastRotation: (r as any).last_rotation,
            riskScore: (r as any).risk_score,
            notes: (r as any).notes,
            metadata: (r as any).metadata,
        }))
    }

    getTokenByFingerprint(fingerprint: string): TokenInventory | undefined {
        const row = this.db.prepare('SELECT * FROM token_inventory WHERE fingerprint = ?').get(fingerprint) as any
        if (!row) return undefined
        return {
            id: row.id,
            tokenType: row.token_type,
            name: row.name,
            source: row.source,
            scopes: row.scopes,
            fingerprint: row.fingerprint,
            firstSeenAt: row.first_seen_at,
            lastSeenAt: row.last_seen_at,
            expiresAt: row.expires_at,
            lastRotation: row.last_rotation,
            riskScore: row.risk_score,
            notes: row.notes,
            metadata: row.metadata,
        }
    }

    updateTokenSeen(fingerprint: string): void {
        this.db.prepare('UPDATE token_inventory SET last_seen_at = ? WHERE fingerprint = ?').run(Date.now(), fingerprint)
    }

    updateTokenRisk(fingerprint: string, riskScore: string, notes?: string): void {
        if (notes !== undefined) {
            this.db.prepare('UPDATE token_inventory SET risk_score = ?, notes = ? WHERE fingerprint = ?').run(riskScore, notes, fingerprint)
        } else {
            this.db.prepare('UPDATE token_inventory SET risk_score = ? WHERE fingerprint = ?').run(riskScore, fingerprint)
        }
    }

    deleteToken(id: number): void {
        this.db.prepare('DELETE FROM token_inventory WHERE id = ?').run(id)
    }

    getTokenStats(): TokenStats {
        const total = (this.db.prepare('SELECT COUNT(*) as c FROM token_inventory').get() as any).c
        const highRisk = (this.db.prepare("SELECT COUNT(*) as c FROM token_inventory WHERE risk_score IN ('high','critical')").get() as any).c
        const now = Date.now()
        const expiringSoon = (this.db.prepare('SELECT COUNT(*) as c FROM token_inventory WHERE expires_at IS NOT NULL AND expires_at > ? AND expires_at < ?').get(now, now + 604800000) as any).c
        const expired = (this.db.prepare('SELECT COUNT(*) as c FROM token_inventory WHERE expires_at IS NOT NULL AND expires_at < ?').get(now) as any).c
        return { total, highRisk, expiringSoon, expired }
    }

    saveScanResult(prNumber: number, scanHash: string, result: { riskScore: number; critical: number; high: number; medium: number; low: number; findings: unknown[]; intel?: unknown; buildIntel?: unknown; state?: string; stateReasons?: string[]; attestation?: unknown }): void {
        this.db.prepare(`
            INSERT OR REPLACE INTO scan_results (pr_number, scan_hash, risk_score, critical, high, medium, low, findings_json, intel_json, build_intel_json, state, state_reasons_json, attestation_json, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(prNumber, scanHash, result.riskScore, result.critical, result.high, result.medium, result.low, JSON.stringify(result.findings), result.intel ? JSON.stringify(result.intel) : '', result.buildIntel ? JSON.stringify(result.buildIntel) : '', result.state || 'PASS', result.stateReasons ? JSON.stringify(result.stateReasons) : '[]', result.attestation ? JSON.stringify(result.attestation) : '', Date.now())
    }

    getLatestScanResult(prNumber: number): ScanResultRow | undefined {
        const rows = this.db.prepare(`
            SELECT pr_number as prNumber, scan_hash as scanHash, risk_score as riskScore,
                   critical, high, medium, low, findings_json as findingsJson, scanned_at as scannedAt,
                   intel_json as intelJson, build_intel_json as buildIntelJson,
                   state, state_reasons_json as stateReasonsJson, attestation_json as attestationJson
            FROM scan_results WHERE pr_number = ? ORDER BY scanned_at DESC LIMIT 1
        `).all(prNumber) as ScanResultRow[]
        return rows.length > 0 ? rows[0] : undefined
    }

    hasScanHash(prNumber: number, scanHash: string): boolean {
        const row = this.db.prepare('SELECT 1 FROM scan_results WHERE pr_number = ? AND scan_hash = ?').get(prNumber, scanHash) as any
        return !!row
    }

    getAllScanResults(): ScanResultRow[] {
        return this.db.prepare(`
            SELECT pr_number as prNumber, scan_hash as scanHash, risk_score as riskScore,
                   critical, high, medium, low, findings_json as findingsJson, scanned_at as scannedAt,
                   intel_json as intelJson, build_intel_json as buildIntelJson,
                   state, state_reasons_json as stateReasonsJson, attestation_json as attestationJson
            FROM scan_results ORDER BY scanned_at DESC
        `).all() as ScanResultRow[]
    }

    saveAnalysisResult(prNumber: number, scanHash: string, result: {
      analysisJson: string
      reviewPriority: string
      impactLevel: string
      complexity: string
      injectionDetected: boolean
      injectionAttemptsJson: string
    }): void {
      this.db.prepare(`
        INSERT OR REPLACE INTO ai_analysis (pr_number, scan_hash, analysis_json, review_priority, impact_level, complexity, injection_detected, injection_attempts_json, analyzed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(prNumber, scanHash, result.analysisJson, result.reviewPriority, result.impactLevel, result.complexity, result.injectionDetected ? 1 : 0, result.injectionAttemptsJson, Date.now())
    }

    getLatestAnalysisResult(prNumber: number): AIAnalysisRow | undefined {
      const rows = this.db.prepare(`
        SELECT pr_number as prNumber, scan_hash as scanHash, analysis_json as analysisJson,
               review_priority as reviewPriority, impact_level as impactLevel, complexity,
               injection_detected as injectionDetected, injection_attempts_json as injectionAttemptsJson,
               analyzed_at as analyzedAt
        FROM ai_analysis WHERE pr_number = ? ORDER BY analyzed_at DESC LIMIT 1
      `).all(prNumber) as AIAnalysisRow[]
      return rows.length > 0 ? rows[0] : undefined
    }

    hasAnalysisHash(prNumber: number, scanHash: string): boolean {
      const row = this.db.prepare('SELECT 1 FROM ai_analysis WHERE pr_number = ? AND scan_hash = ?').get(prNumber, scanHash) as any
      return !!row
    }

    saveExplanation(prNumber: number, type: 'pr' | 'scan', summary: string[], argumentation: string): void {
      this.db.prepare(`
        INSERT OR REPLACE INTO saved_explanations (pr_number, type, summary_json, argumentation, saved_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(prNumber, type, JSON.stringify(summary), argumentation, Date.now())
    }

    getSavedExplanation(prNumber: number, type: 'pr' | 'scan'): SavedExplanationRow | undefined {
      const row = this.db.prepare(`
        SELECT pr_number as prNumber, type, summary_json as summaryJson, argumentation, saved_at as savedAt
        FROM saved_explanations WHERE pr_number = ? AND type = ?
      `).get(prNumber, type) as any
      return row || undefined
    }

    addBlacklistPR(prNumber: number, owner: string, repo: string, title: string, author: string, sha: string, reason: string): void {
      this.db.prepare(`
        INSERT OR REPLACE INTO blacklist_prs (pr_number, owner, repo, title, author, sha, reason, saved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(prNumber, owner, repo, title, author, sha, reason, Date.now())
    }

    removeBlacklistPR(prNumber: number): void {
      this.db.prepare('DELETE FROM blacklist_prs WHERE pr_number = ?').run(prNumber)
    }

    getBlacklistPR(prNumber: number): BlacklistPRRow | undefined {
      const row = this.db.prepare(`
        SELECT pr_number as prNumber, owner, repo, title, author, sha, reason, saved_at as savedAt
        FROM blacklist_prs WHERE pr_number = ?
      `).get(prNumber) as any
      return row || undefined
    }

    getAllBlacklistPRs(): BlacklistPRRow[] {
      return this.db.prepare(`
        SELECT pr_number as prNumber, owner, repo, title, author, sha, reason, saved_at as savedAt
        FROM blacklist_prs ORDER BY saved_at DESC
      `).all() as BlacklistPRRow[]
    }

    close(): void {
        this.db.close();
    }
}
