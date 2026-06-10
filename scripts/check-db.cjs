const Database = require('better-sqlite3');
const path = require('path');
const os = require('os');

const dbPath = path.join(os.homedir(), '.sentinel-oracle', 'oracle.db');
const db = new Database(dbPath);

console.log('=== DB STATE ===');
console.log('PRs:', JSON.stringify(db.prepare('SELECT * FROM pending_prs').all(), null, 2));
console.log('Sessions:', JSON.stringify(db.prepare('SELECT id, device_name, expires_at, last_used_at FROM sessions').all(), null, 2));
console.log('Challenges:', JSON.stringify(db.prepare('SELECT * FROM challenges').all(), null, 2));
console.log('Config:', JSON.stringify(db.prepare('SELECT * FROM config').all(), null, 2));
console.log('Devices:', JSON.stringify(db.prepare('SELECT id, name, credential_id FROM auth_devices').all(), null, 2));

db.close();
