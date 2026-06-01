"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IntegrityChain = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const crypto = __importStar(require("crypto"));
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
class IntegrityChain {
    constructor() {
        const dbPath = path.join(os.homedir(), '.sentinel', 'vault.db');
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir))
            fs.mkdirSync(dir, { recursive: true });
        this.db = new better_sqlite3_1.default(dbPath);
        this.cliRoot = path.join(__dirname, '..', '..', '..');
        this.sessionId = crypto.randomBytes(8).toString('hex');
        this.sessionStart = Date.now();
        this.initSchema();
    }
    initSchema() {
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
    recordBoot(codeHash) {
        const lastLink = this.getLastLink();
        let accumulated = 0;
        let chainStatus = 'INTACT';
        let previousHash = null;
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
        stmt.run(linkData.session_id, linkData.link_number, linkData.code_hash, linkData.previous_link_hash, linkData.link_hash, linkData.started_at, linkData.accumulated_seconds);
        const inserted = this.getLastLink();
        const status = {
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
    getStatus() {
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
        let chainStatus = 'INTACT';
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
    getLastLink() {
        const row = this.db.prepare('SELECT * FROM integrity_chain ORDER BY id DESC LIMIT 1').get();
        return row || null;
    }
    getAllLinks() {
        return this.db.prepare('SELECT * FROM integrity_chain ORDER BY id ASC').all();
    }
    getTotalLinks() {
        const r = this.db.prepare('SELECT COUNT(*) as c FROM integrity_chain').get();
        return r.c;
    }
    hashLink(data) {
        return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    }
    hashObject(data) {
        const sorted = {};
        Object.keys(data).sort().forEach(k => { sorted[k] = data[k]; });
        return crypto.createHash('sha256').update(JSON.stringify(sorted)).digest('hex');
    }
    formatDuration(totalSeconds) {
        const d = Math.floor(totalSeconds / 86400);
        const h = Math.floor((totalSeconds % 86400) / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = Math.floor(totalSeconds % 60);
        const parts = [];
        if (d > 0)
            parts.push(`${d}d`);
        if (h > 0)
            parts.push(`${h}h`);
        if (m > 0)
            parts.push(`${m}m`);
        parts.push(`${s}s`);
        return parts.join(' ');
    }
}
exports.IntegrityChain = IntegrityChain;
