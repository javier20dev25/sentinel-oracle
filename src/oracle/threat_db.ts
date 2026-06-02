import * as path from 'path';
import * as fs from 'fs';
import Database from 'better-sqlite3';

const DB_DIR = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.sentinel');
const DB_FILE = path.join(DB_DIR, 'threats.db');

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (!db) {
    if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
    db = new Database(DB_FILE);
    db.pragma('journal_mode = WAL');
    initSchema();
  }
  return db;
}

function initSchema(): void {
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

// --- Threat records ---

export interface ThreatRecord {
  id?: number;
  type: 'pr' | 'package' | 'author' | 'pattern';
  source: string;
  author?: string;
  authorEmail?: string;
  title?: string;
  severity?: string;
  findings?: string;
  signature?: string;
  diffHash?: string;
  notes?: string;
  detected_at?: string;
}

export function addThreat(t: ThreatRecord): number {
  const d = getDb();
  const stmt = d.prepare(`
    INSERT INTO threats (type, source, author, author_email, title, severity, findings, signature, diff_hash, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(t.type, t.source, t.author || null, t.authorEmail || null, t.title || null,
    t.severity || 'HIGH', t.findings || null, t.signature || null, t.diffHash || null, t.notes || null);

  // Update threat_authors
  if (t.author) {
    const existing = d.prepare('SELECT * FROM threat_authors WHERE author = ?').get(t.author) as any;
    if (existing) {
      d.prepare('UPDATE threat_authors SET last_seen = datetime(\'now\'), threat_count = threat_count + 1 WHERE author = ?').run(t.author);
    } else {
      d.prepare('INSERT OR IGNORE INTO threat_authors (author, email, patterns, repos) VALUES (?, ?, ?, ?)').run(
        t.author, t.authorEmail || null, JSON.stringify([t.type]), JSON.stringify([t.source])
      );
    }
  }

  return Number(result.lastInsertRowid);
}

export function getThreatsByAuthor(author: string): ThreatRecord[] {
  const d = getDb();
  return d.prepare('SELECT * FROM threats WHERE author = ? ORDER BY detected_at DESC').all(author) as ThreatRecord[];
}

export function getThreatsBySignature(sig: string): ThreatRecord[] {
  const d = getDb();
  return d.prepare('SELECT * FROM threats WHERE signature = ? ORDER BY detected_at DESC').all(sig) as ThreatRecord[];
}

export function getRecentThreats(limit = 20): ThreatRecord[] {
  const d = getDb();
  return d.prepare('SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?').all(limit) as ThreatRecord[];
}

// --- Threat authors ---

export interface ThreatAuthor {
  author: string;
  email?: string;
  first_seen: string;
  last_seen: string;
  threat_count: number;
  patterns: string;
  risk_level: string;
  repos: string;
}

export function getThreatAuthor(author: string): ThreatAuthor | null {
  const d = getDb();
  return d.prepare('SELECT * FROM threat_authors WHERE author = ?').get(author) as ThreatAuthor | null;
}

export function getHighRiskAuthors(): ThreatAuthor[] {
  const d = getDb();
  return d.prepare("SELECT * FROM threat_authors WHERE risk_level IN ('HIGH', 'CRITICAL') ORDER BY threat_count DESC").all() as ThreatAuthor[];
}

export function setAuthorRiskLevel(author: string, level: string): void {
  const d = getDb();
  d.prepare('UPDATE threat_authors SET risk_level = ? WHERE author = ?').run(level, author);
}

// --- Threat patterns ---

export function addThreatPattern(pattern: string, description: string, severity = 'MEDIUM'): void {
  const d = getDb();
  const existing = d.prepare('SELECT * FROM threat_patterns WHERE pattern = ?').get(pattern) as any;
  if (existing) {
    d.prepare('UPDATE threat_patterns SET occurrence_count = occurrence_count + 1, last_seen = datetime(\'now\') WHERE pattern = ?').run(pattern);
  } else {
    d.prepare('INSERT INTO threat_patterns (pattern, description, severity) VALUES (?, ?, ?)').run(pattern, description, severity);
  }
}

export function getThreatPatterns(severity?: string): any[] {
  const d = getDb();
  if (severity) {
    return d.prepare('SELECT * FROM threat_patterns WHERE severity = ? ORDER BY occurrence_count DESC').all(severity);
  }
  return d.prepare('SELECT * FROM threat_patterns ORDER BY occurrence_count DESC').all();
}

// --- Correlation ---

export interface CorrelationResult {
  threatCount: number;
  knownAuthor: boolean;
  authorThreats: ThreatRecord[];
  authorRiskLevel: string;
  patternMatches: any[];
}

export function correlateFindings(
  author?: string,
  findings?: string,
  diffHash?: string
): CorrelationResult {
  const result: CorrelationResult = {
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

export function closeDb(): void {
  if (db) { db.close(); db = null; }
}
