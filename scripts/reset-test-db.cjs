const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const os = require('os');

const dbPath = path.join(os.homedir(), '.sentinel-oracle', 'oracle.db');
const db = new Database(dbPath);
const now = Date.now();

// Reset PR to pending with fresh timestamp
const credId = db.prepare('SELECT credential_id FROM auth_devices LIMIT 1').pluck().get();

db.prepare('UPDATE pending_prs SET auth_status = ?, sentinel_status = ?, authorized_at = NULL, created_at = ? WHERE pr_number = ?').run('pending', 'missing', now, 142);

// Refresh session
const sessionId = uuidv4();
db.prepare('DELETE FROM sessions').run();
db.prepare('INSERT INTO sessions (id, credential_id, device_name, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)').run(
  sessionId, credId, 'Admin Phone', now, now + 86400000, now
);

// Clear challenges and unlock
db.prepare('DELETE FROM challenges').run();
db.prepare('DELETE FROM config WHERE key = ?').run('system_lockdown');

console.log(sessionId);
db.close();
