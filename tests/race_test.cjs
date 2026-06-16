// Race condition test: fire 2 simultaneous confirms for the same challenge
// Run: node tests/race_test.cjs
const https = require('https');
const { createCipheriv, createHmac, randomBytes } = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');
const os = require('os');
const Database = require('better-sqlite3');

const ALGORITHM = 'aes-256-gcm';
const url = 'https://desktop-ki5app4.tail35419a.ts.net';

function post(path, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url + path);
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: u.hostname, port: u.port, path: u.pathname,
      method: 'POST', rejectUnauthorized: false, agent: false,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, res => {
      let text = '';
      res.on('data', c => text += c);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function encrypt(plaintext, key) {
    const iv = randomBytes(16);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

async function main() {
  const dbPath = path.join(os.homedir(), '.sentinel-oracle/oracle.db');
  const db = new Database(dbPath);

  const encKey = readFileSync(path.join(os.homedir(), '.sentinel-oracle/.encryption_key'));
  const hmacSeed = readFileSync(path.join(os.homedir(), '.sentinel-oracle/.hmac_seed'));
  const hmacKey = createHmac('sha256', hmacSeed).update('sentinel-oracle-hmac-key-v1').digest();

  // Find a PR in 'pending' status, or reset one
  let target = db.prepare('SELECT pr_number FROM pending_prs WHERE auth_status = ? LIMIT 1').get('pending');
  if (!target) {
    target = db.prepare('SELECT pr_number FROM pending_prs LIMIT 1').get();
    if (!target) { console.log('FAIL: No PRs in DB'); process.exit(1); }
    db.prepare('UPDATE pending_prs SET auth_status = ? WHERE pr_number = ?').run('pending', target.pr_number);
  }
  const prNumber = target.pr_number;

  const challengeId = require('uuid').v4();
  const timestamp = Date.now();
  const payload = `${challengeId}:${prNumber}:${timestamp}`;
  const signature = createHmac('sha256', hmacKey).update(payload).digest('hex');
  const expiresAt = Date.now() + 120000;

  const storedData = JSON.stringify({
    v: 1, cid: challengeId, pr: prNumber,
    ts: timestamp, sig: signature, exp: expiresAt,
    url: `${url}/authorize?cid=${challengeId}&pr=${prNumber}`
  });

  const encryptedData = encrypt(storedData, encKey);
  db.prepare('INSERT INTO challenges (id, pr_number, type, data, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(challengeId, prNumber, 'authorization', encryptedData, expiresAt, Date.now());
  db.close();

  console.log('=== RACE CONDITION TEST ===');
  console.log('Challenge:', challengeId, 'PR:', prNumber);
  console.log('Sending 2 simultaneous confirm requests...');

  const body = JSON.stringify({
    challengeId,
    credential: { id: 'test', response: { authenticatorData: 'fake', signature: 'fake', clientDataJSON: 'fake' } },
    challenge: 'test-webauthn-challenge',
    reason: 'Race test'
  });

  const [r1, r2] = await Promise.all([
    post(`/api/prs/${prNumber}/confirm`, JSON.parse(body)),
    post(`/api/prs/${prNumber}/confirm`, JSON.parse(body))
  ]);

  console.log('Request 1 - Status:', r1.status, '=>', JSON.stringify(r1.body));
  console.log('Request 2 - Status:', r2.status, '=>', JSON.stringify(r2.body));

  const db2 = new Database(dbPath);
  const check = db2.prepare('SELECT id, used FROM challenges WHERE id = ?').get(challengeId);
  db2.close();
  console.log('DB state:', JSON.stringify(check));

  const errors = [r1.body.error, r2.body.error];
  const usedCount = errors.filter(e => e === 'Challenge already used').length;

  if (usedCount >= 1 && check && check.used === 1) {
    console.log('PASS: Race handled correctly - challenge consumed once, second request rejected');
    process.exit(0);
  } else {
    console.log('FAIL: Unexpected result');
    process.exit(1);
  }
}
main().catch(e => { console.error(e); process.exit(1); });
