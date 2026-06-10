const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const os = require('os');

const dbPath = path.join(os.homedir(), '.sentinel-oracle', 'oracle.db');
const db = new Database(dbPath);
const sessionId = uuidv4();
const now = Date.now();

const credId = db.prepare('SELECT credential_id FROM auth_devices LIMIT 1').pluck().get();

db.prepare('DELETE FROM sessions').run();
db.prepare('INSERT INTO sessions (id, credential_id, device_name, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)').run(
  sessionId, credId, 'Admin Phone', now, now + 86400000, now
);

// Also reset the PR auth_status to pending and unlocked
db.prepare('UPDATE pending_prs SET auth_status = ?, sentinel_status = ? WHERE pr_number = ?').run('pending', 'missing', 142);

// Delete any stale challenges
db.prepare('DELETE FROM challenges WHERE pr_number = ?').run(142);

// Reset lockdown state
db.prepare('DELETE FROM config WHERE key = ?').run('locked');

console.log('NEW_SESSION_ID=' + sessionId);
db.close();
