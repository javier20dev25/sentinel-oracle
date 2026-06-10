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
    private encryptionKey: Buffer;
    private idleTimeoutMs: number;

    constructor(dataDir: string, encryptionKey?: Buffer, idleTimeoutMs = 1800000) {
        this.db = new Database(path.join(dataDir, 'oracle.db'));
        this.db.pragma('journal_mode = WAL');
        this.encryptionKey = encryptionKey || Buffer.alloc(0);
        this.idleTimeoutMs = idleTimeoutMs;
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
        try { this.db.prepare('ALTER TABLE pending_prs ADD COLUMN device_name TEXT').run() } catch {}
    }

    upsertPR(pr: Omit<PendingPR, 'id'>): void {
        this.db.prepare(`
            INSERT INTO pending_prs (pr_number, owner, repo, title, author, sha, ci_status, sentinel_status, auth_status, created_at, authorized_at, device_name)
            VALUES (@prNumber, @owner, @repo, @title, @author, @sha, @ciStatus, @sentinelStatus, @authStatus, @createdAt, @authorizedAt, @deviceName)
            ON CONFLICT(pr_number) DO UPDATE SET
                sha = excluded.sha,
                ci_status = excluded.ci_status,
                sentinel_status = excluded.sentinel_status,
                auth_status = excluded.auth_status,
                title = excluded.title,
                device_name = excluded.device_name
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

    createSession(credentialId: string, deviceName: string, ttlMs: number): string {
        const { v4: uuidv4 } = require('uuid')
        const id = uuidv4()
        const now = Date.now()
        this.db.prepare(`
            INSERT INTO sessions (id, credential_id, device_name, created_at, expires_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(id, credentialId, deviceName, now, now + ttlMs, now)
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

    close(): void {
        this.db.close();
    }
}
