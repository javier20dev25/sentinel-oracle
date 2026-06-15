import Database from 'better-sqlite3';
import * as path from 'path';
import { encrypt, decrypt } from './encryption';

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
      } catch (err) {
        console.error(`[db] Migration warning: ${sql} — ${err instanceof Error ? err.message : err}`)
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
            CREATE INDEX IF NOT EXISTS idx_pr_files_pr ON pr_files(pr_number);
            CREATE INDEX IF NOT EXISTS idx_pr_files_filename ON pr_files(filename);
            CREATE INDEX IF NOT EXISTS idx_pr_files_auth ON pr_files(auth_status);
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

    close(): void {
        this.db.close();
    }
}
