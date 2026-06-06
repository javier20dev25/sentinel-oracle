import Database from 'better-sqlite3';
import * as path from 'path';

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

export interface AuditEntry {
    id: number;
    timestamp: number;
    action: string;
    prNumber: number | null;
    detail: string;
}

export class DatabaseStore {
    private db: Database.Database;

    constructor(dataDir: string) {
        this.db = new Database(path.join(dataDir, 'oracle.db'));
        this.db.pragma('journal_mode = WAL');
        this.migrate();
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
                authorized_at INTEGER
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
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        `);
    }

    upsertPR(pr: Omit<PendingPR, 'id'>): void {
        this.db.prepare(`
            INSERT INTO pending_prs (pr_number, owner, repo, title, author, sha, ci_status, sentinel_status, auth_status, created_at, authorized_at)
            VALUES (@prNumber, @owner, @repo, @title, @author, @sha, @ciStatus, @sentinelStatus, @authStatus, @createdAt, @authorizedAt)
            ON CONFLICT(pr_number) DO UPDATE SET
                sha = excluded.sha,
                ci_status = excluded.ci_status,
                sentinel_status = excluded.sentinel_status,
                auth_status = excluded.auth_status,
                title = excluded.title
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
        }
    }

    getPendingPRs(): PendingPR[] {
        const rows = this.db.prepare(
            'SELECT * FROM pending_prs WHERE auth_status = ? ORDER BY created_at DESC'
        ).all('pending')
        return rows.map(r => this.mapPR(r))
    }

    getPRByNumber(prNumber: number): PendingPR | undefined {
        const row = this.db.prepare(
            'SELECT * FROM pending_prs WHERE pr_number = ?'
        ).get(prNumber)
        return row ? this.mapPR(row) : undefined
    }

    setAuthStatus(prNumber: number, status: PendingPR['authStatus']): void {
        this.db.prepare(
            'UPDATE pending_prs SET auth_status = ?, authorized_at = ? WHERE pr_number = ?'
        ).run(status, status === 'authorized' ? Date.now() : null, prNumber);
    }

    registerDevice(device: Omit<AuthDevice, 'id' | 'createdAt' | 'lastUsedAt'>): void {
        this.db.prepare(`
            INSERT INTO auth_devices (name, credential_id, public_key, counter, transports, created_at)
            VALUES (@name, @credentialId, @publicKey, @counter, @transports, @createdAt)
        `).run({ ...device, createdAt: Date.now() });
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
        return row ? this.mapDevice(row) : undefined
    }

    listDevices(): AuthDevice[] {
        const rows = this.db.prepare(
            'SELECT * FROM auth_devices ORDER BY created_at DESC'
        ).all()
        return rows.map(r => this.mapDevice(r))
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
        this.db.prepare(`
            INSERT INTO challenges (id, pr_number, type, data, expires_at, used, created_at)
            VALUES (?, ?, 'authorization', ?, ?, 0, ?)
        `).run(id, prNumber, data, expiresAt, Date.now());
    }

    consumeChallenge(id: string): { prNumber: number; data: string } | null {
        const row = this.db.prepare(
            'SELECT id, pr_number, data, expires_at, used FROM challenges WHERE id = ?'
        ).get(id) as { id: string; pr_number: number; data: string; expires_at: number; used: number } | undefined;

        if (!row || row.used !== 0 || Date.now() > row.expires_at) return null;

        this.db.prepare('UPDATE challenges SET used = 1 WHERE id = ?').run(id);
        return { prNumber: row.pr_number, data: row.data };
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

    close(): void {
        this.db.close();
    }
}
