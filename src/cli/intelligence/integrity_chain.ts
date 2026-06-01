import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import Database from 'better-sqlite3';

export interface ChainLink {
    id: number;
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    link_hash: string;
    started_at: string;
    accumulated_seconds: number;
    created_at: string;
    [key: string]: unknown;
}

interface ChainLinkInput {
    session_id: string;
    link_number: number;
    code_hash: string;
    previous_link_hash: string | null;
    started_at: string;
    accumulated_seconds: number;
    link_hash?: string;
    [key: string]: unknown;
}

export interface ChainStatus {
    status: 'INTACT' | 'BROKEN' | 'EMPTY';
    totalLinks: number;
    currentCodeHash: string;
    lastLink: ChainLink | null;
    accumulatedSeconds: number;
    sessionSeconds: number;
    chainStart: string;
    lastVerified: string;
}

export class IntegrityChain {
    private db: Database.Database;
    private cliRoot: string;
    private sessionId: string;
    private sessionStart: number;

    constructor() {
        const dbPath = path.join(os.homedir(), '.sentinel', 'vault.db');
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        this.db = new Database(dbPath);
        this.cliRoot = path.join(__dirname, '..', '..', '..');
        this.sessionId = crypto.randomBytes(8).toString('hex');
        this.sessionStart = Date.now();
        this.initSchema();
    }

    private initSchema(): void {
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS integrity_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                link_number INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                previous_link_hash TEXT,
                link_hash TEXT NOT NULL,
                started_at TEXT NOT NULL,
                accumulated_seconds REAL NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
    }

    public recordBoot(codeHash: string): { chainStatus: ChainStatus } {
        const lastLink = this.getLastLink();
        let accumulated = 0;
        let chainStatus: 'INTACT' | 'BROKEN' | 'EMPTY' = 'INTACT';
        let previousHash: string | null = null;

        if (lastLink) {
            previousHash = this.hashLink(lastLink);
            const recomputed = crypto.createHash('sha256').update(previousHash).digest('hex');
            if (recomputed !== lastLink.link_hash) {
                chainStatus = 'BROKEN';
            }

            if (lastLink.code_hash !== codeHash) {
                chainStatus = 'BROKEN';
            }

            const lastTime = new Date(lastLink.created_at).getTime();
            const elapsed = Math.max(0, (this.sessionStart - lastTime) / 1000);
            accumulated = lastLink.accumulated_seconds + elapsed;
        }

        const linkHash = this.hashLink({
            session_id: this.sessionId,
            link_number: lastLink ? lastLink.link_number + 1 : 1,
            code_hash: codeHash,
            previous_link_hash: previousHash,
            started_at: new Date(this.sessionStart).toISOString(),
            accumulated_seconds: accumulated,
        });

        const linkData = {
            session_id: this.sessionId,
            link_number: lastLink ? lastLink.link_number + 1 : 1,
            code_hash: codeHash,
            previous_link_hash: previousHash,
            link_hash: linkHash,
            started_at: new Date(this.sessionStart).toISOString(),
            accumulated_seconds: accumulated,
        };

        const stmt = this.db.prepare(`
            INSERT INTO integrity_chain (session_id, link_number, code_hash, previous_link_hash, link_hash, started_at, accumulated_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            linkData.session_id,
            linkData.link_number,
            linkData.code_hash,
            linkData.previous_link_hash,
            linkData.link_hash,
            linkData.started_at,
            linkData.accumulated_seconds
        );

        const inserted = this.getLastLink()!;
        const status: ChainStatus = {
            status: chainStatus,
            totalLinks: this.getTotalLinks(),
            currentCodeHash: codeHash,
            lastLink: inserted,
            accumulatedSeconds: accumulated,
            sessionSeconds: 0,
            chainStart: lastLink ? lastLink.started_at : inserted.started_at,
            lastVerified: new Date().toISOString(),
        };

        return { chainStatus: status };
    }

    public getStatus(): ChainStatus {
        const lastLink = this.getLastLink();
        if (!lastLink) {
            return {
                status: 'EMPTY',
                totalLinks: 0,
                currentCodeHash: '',
                lastLink: null,
                accumulatedSeconds: 0,
                sessionSeconds: 0,
                chainStart: '',
                lastVerified: '',
            };
        }

        let chainStatus: 'INTACT' | 'BROKEN' | 'EMPTY' = 'INTACT';
        let current = lastLink;
        const allLinks = this.getAllLinks();

        for (let i = allLinks.length - 1; i >= 1; i--) {
            const link = allLinks[i];
            const prev = allLinks[i - 1];
            const prevHash = this.hashObject(prev);
            if (prevHash !== link.previous_link_hash) {
                chainStatus = 'BROKEN';
                break;
            }
        }

        const elapsed = (Date.now() - new Date(lastLink.created_at).getTime()) / 1000;
        return {
            status: chainStatus,
            totalLinks: allLinks.length,
            currentCodeHash: lastLink.code_hash,
            lastLink,
            accumulatedSeconds: lastLink.accumulated_seconds + elapsed,
            sessionSeconds: elapsed,
            chainStart: allLinks[0].started_at,
            lastVerified: new Date().toISOString(),
        };
    }

    private getLastLink(): ChainLink | null {
        const row = this.db.prepare(
            'SELECT * FROM integrity_chain ORDER BY id DESC LIMIT 1'
        ).get() as ChainLink | undefined;
        return row || null;
    }

    private getAllLinks(): ChainLink[] {
        return this.db.prepare(
            'SELECT * FROM integrity_chain ORDER BY id ASC'
        ).all() as ChainLink[];
    }

    private getTotalLinks(): number {
        const r = this.db.prepare('SELECT COUNT(*) as c FROM integrity_chain').get() as { c: number };
        return r.c;
    }

    private hashLink(data: ChainLinkInput): string {
        return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    }

    private hashObject(data: Record<string, unknown>): string {
        const sorted: Record<string, unknown> = {};
        Object.keys(data).sort().forEach(k => { sorted[k] = data[k]; });
        return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
    }

    public formatDuration(totalSeconds: number): string {
        const d = Math.floor(totalSeconds / 86400);
        const h = Math.floor((totalSeconds % 86400) / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = Math.floor(totalSeconds % 60);
        const parts: string[] = [];
        if (d > 0) parts.push(`${d}d`);
        if (h > 0) parts.push(`${h}h`);
        if (m > 0) parts.push(`${m}m`);
        parts.push(`${s}s`);
        return parts.join(' ');
    }
}
