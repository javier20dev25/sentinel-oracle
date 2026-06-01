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
exports.addThreat = addThreat;
exports.getThreatsByAuthor = getThreatsByAuthor;
exports.getThreatsBySignature = getThreatsBySignature;
exports.getRecentThreats = getRecentThreats;
exports.getThreatAuthor = getThreatAuthor;
exports.getHighRiskAuthors = getHighRiskAuthors;
exports.setAuthorRiskLevel = setAuthorRiskLevel;
exports.addThreatPattern = addThreatPattern;
exports.getThreatPatterns = getThreatPatterns;
exports.correlateFindings = correlateFindings;
exports.closeDb = closeDb;
const path = __importStar(require("path"));
const better_sqlite3_1 = __importDefault(require("better-sqlite3"));
const DB_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel');
const DB_FILE = path.join(DB_DIR, 'threats.db');
let db = null;
function getDb() {
    if (!db) {
        const fs = require('fs');
        if (!fs.existsSync(DB_DIR))
            fs.mkdirSync(DB_DIR, { recursive: true });
        db = new better_sqlite3_1.default(DB_FILE);
        db.pragma('journal_mode = WAL');
        initSchema();
    }
    return db;
}
function initSchema() {
    const d = getDb();
    d.exec(`
    CREATE TABLE IF NOT EXISTS threats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      source TEXT NOT NULL,
      author TEXT,
      author_email TEXT,
      title TEXT,
      severity TEXT NOT NULL DEFAULT 'HIGH',
      findings TEXT,
      signature TEXT,
      diff_hash TEXT,
      detected_at TEXT NOT NULL DEFAULT (datetime('now')),
      notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_threats_author ON threats(author);
    CREATE INDEX IF NOT EXISTS idx_threats_signature ON threats(signature);
    CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(type);

    CREATE TABLE IF NOT EXISTS threat_authors (
      author TEXT PRIMARY KEY,
      email TEXT,
      first_seen TEXT NOT NULL DEFAULT (datetime('now')),
      last_seen TEXT NOT NULL DEFAULT (datetime('now')),
      threat_count INTEGER NOT NULL DEFAULT 1,
      patterns TEXT DEFAULT '[]',
      risk_level TEXT NOT NULL DEFAULT 'MEDIUM',
      repos TEXT DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_ta_risk ON threat_authors(risk_level);

    CREATE TABLE IF NOT EXISTS threat_patterns (
      pattern TEXT PRIMARY KEY,
      description TEXT,
      severity TEXT NOT NULL DEFAULT 'MEDIUM',
      first_seen TEXT NOT NULL DEFAULT (datetime('now')),
      occurrence_count INTEGER NOT NULL DEFAULT 1
    );
  `);
}
function addThreat(t) {
    const d = getDb();
    const stmt = d.prepare(`
    INSERT INTO threats (type, source, author, author_email, title, severity, findings, signature, diff_hash, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
    const result = stmt.run(t.type, t.source, t.author || null, t.authorEmail || null, t.title || null, t.severity || 'HIGH', t.findings || null, t.signature || null, t.diffHash || null, t.notes || null);
    // Update threat_authors
    if (t.author) {
        const existing = d.prepare('SELECT * FROM threat_authors WHERE author = ?').get(t.author);
        if (existing) {
            d.prepare('UPDATE threat_authors SET last_seen = datetime(\'now\'), threat_count = threat_count + 1 WHERE author = ?').run(t.author);
        }
        else {
            d.prepare('INSERT OR IGNORE INTO threat_authors (author, email, patterns, repos) VALUES (?, ?, ?, ?)').run(t.author, t.authorEmail || null, JSON.stringify([t.type]), JSON.stringify([t.source]));
        }
    }
    return Number(result.lastInsertRowid);
}
function getThreatsByAuthor(author) {
    const d = getDb();
    return d.prepare('SELECT * FROM threats WHERE author = ? ORDER BY detected_at DESC').all(author);
}
function getThreatsBySignature(sig) {
    const d = getDb();
    return d.prepare('SELECT * FROM threats WHERE signature = ? ORDER BY detected_at DESC').all(sig);
}
function getRecentThreats(limit = 20) {
    const d = getDb();
    return d.prepare('SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?').all(limit);
}
function getThreatAuthor(author) {
    const d = getDb();
    return d.prepare('SELECT * FROM threat_authors WHERE author = ?').get(author);
}
function getHighRiskAuthors() {
    const d = getDb();
    return d.prepare("SELECT * FROM threat_authors WHERE risk_level IN ('HIGH', 'CRITICAL') ORDER BY threat_count DESC").all();
}
function setAuthorRiskLevel(author, level) {
    const d = getDb();
    d.prepare('UPDATE threat_authors SET risk_level = ? WHERE author = ?').run(level, author);
}
// --- Threat patterns ---
function addThreatPattern(pattern, description, severity = 'MEDIUM') {
    const d = getDb();
    const existing = d.prepare('SELECT * FROM threat_patterns WHERE pattern = ?').get(pattern);
    if (existing) {
        d.prepare('UPDATE threat_patterns SET occurrence_count = occurrence_count + 1, last_seen = datetime(\'now\') WHERE pattern = ?').run(pattern);
    }
    else {
        d.prepare('INSERT INTO threat_patterns (pattern, description, severity) VALUES (?, ?, ?)').run(pattern, description, severity);
    }
}
function getThreatPatterns(severity) {
    const d = getDb();
    if (severity) {
        return d.prepare('SELECT * FROM threat_patterns WHERE severity = ? ORDER BY occurrence_count DESC').all(severity);
    }
    return d.prepare('SELECT * FROM threat_patterns ORDER BY occurrence_count DESC').all();
}
function correlateFindings(author, findings, diffHash) {
    const result = {
        threatCount: 0,
        knownAuthor: false,
        authorThreats: [],
        authorRiskLevel: 'unknown',
        patternMatches: [],
    };
    // Check author
    if (author) {
        const ta = getThreatAuthor(author);
        if (ta) {
            result.knownAuthor = true;
            result.authorRiskLevel = ta.risk_level;
            result.authorThreats = getThreatsByAuthor(author);
            result.threatCount += ta.threat_count;
        }
    }
    // Check diff hash
    if (diffHash) {
        const sigMatches = getThreatsBySignature(diffHash);
        result.threatCount += sigMatches.length;
    }
    // Check findings patterns
    if (findings) {
        const patterns = getThreatPatterns();
        for (const p of patterns) {
            if (findings.toLowerCase().includes(p.pattern.toLowerCase())) {
                result.patternMatches.push(p);
            }
        }
    }
    return result;
}
function closeDb() {
    if (db) {
        db.close();
        db = null;
    }
}
