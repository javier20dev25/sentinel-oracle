const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const dbPath = path.join(os.homedir(), '.sentinel-oracle', 'oracle.db');
// Remove old DB
try { require('fs').unlinkSync(dbPath); } catch {}
try { require('fs').unlinkSync(dbPath + '-wal'); } catch {}
try { require('fs').unlinkSync(dbPath + '-shm'); } catch {}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS pending_prs (id INTEGER PRIMARY KEY AUTOINCREMENT, pr_number INTEGER NOT NULL UNIQUE, owner TEXT NOT NULL, repo TEXT NOT NULL, title TEXT NOT NULL, author TEXT NOT NULL, sha TEXT NOT NULL, ci_status TEXT NOT NULL DEFAULT 'unknown', sentinel_status TEXT NOT NULL DEFAULT 'unknown', auth_status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, authorized_at INTEGER);
  CREATE TABLE IF NOT EXISTS auth_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL, last_used_at INTEGER);
  CREATE TABLE IF NOT EXISTS challenges (id TEXT PRIMARY KEY, pr_number INTEGER NOT NULL, type TEXT NOT NULL DEFAULT 'authorization', data TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, action TEXT NOT NULL, pr_number INTEGER, detail TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, device_name TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

// Mark enrollment completed
db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run('enrollment_completed', 'true');

// Register a legitimate device (mocked WebAuthn credential)
const credId = crypto.randomBytes(32).toString('base64url');
db.prepare(`INSERT INTO auth_devices (name, credential_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)`).run(
  'Admin Phone', credId, crypto.randomBytes(65).toString('base64url'), 5, JSON.stringify(['internal']), Date.now()
);
console.log('Device registered: credentialId=' + credId.slice(0, 16) + '...');

// Insert test PR
db.prepare(`INSERT INTO pending_prs (pr_number, owner, repo, title, author, sha, ci_status, sentinel_status, auth_status, created_at, authorized_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
  142, 'test-owner', 'test-repo', 'Fix critical security bug', 'maria', 'abc123def456', 'passed', 'missing', 'pending', Date.now(), null
);
console.log('PR #142 inserted (pending auth)');

// Create a valid session for the admin so we can use it in tests
const { v4: uuidv4 } = require('uuid');
const sessionId = uuidv4();
const now = Date.now();
db.prepare('INSERT INTO sessions (id, credential_id, device_name, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)').run(
  sessionId, credId, 'Admin Phone', now, now + 86400000, now
);
console.log('Session created: ' + sessionId);
console.log('SESSION_ID=' + sessionId);

db.close();
console.log('\nTest DB ready at: ' + dbPath);
