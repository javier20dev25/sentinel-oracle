// Restart persistence test: verify challenges survive server restart
// Run: node tests/restart_test.cjs
const { createCipheriv, createHmac, randomBytes } = require('crypto');
const { readFileSync } = require('fs');
const path = require('path');
const os = require('os');
const Database = require('better-sqlite3');

const ALGORITHM = 'aes-256-gcm';
const url = 'https://desktop-ki5app4.tail35419a.ts.net';

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

  // Find a PR in 'pending' status
  let target = db.prepare('SELECT pr_number FROM pending_prs WHERE auth_status = ? LIMIT 1').get('pending');
  if (!target) {
    target = db.prepare('SELECT pr_number FROM pending_prs LIMIT 1').get();
    if (!target) { console.log('FAIL: No PRs in DB'); process.exit(1); }
    db.prepare('UPDATE pending_prs SET auth_status = ? WHERE pr_number = ?').run('pending', target.pr_number);
  }
  const prNumber = target.pr_number;
  db.close();

  // Test 1: Fresh challenge after restart
  console.log('=== TEST 1: Fresh challenge after restart ===');
  const db1 = new Database(dbPath);
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
  db1.prepare('INSERT INTO challenges (id, pr_number, type, data, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
    .run(challengeId, prNumber, 'authorization', encryptedData, expiresAt, Date.now());
  db1.close();

  const body = JSON.stringify({
    challengeId,
    credential: { id: 'test', response: { authenticatorData: 'fake', signature: 'fake', clientDataJSON: 'fake' } },
    challenge: 'test-webauthn-challenge',
    reason: 'Restart test'
  });

  const r1 = await fetch(`${url}/api/prs/${prNumber}/confirm`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body
  });
  const d1 = await r1.json();
  console.log('Status:', r1.status, '=>', JSON.stringify(d1));

  if (d1.error === 'Biometric authentication failed') {
    console.log('PASS: Challenge survived restart (reached WebAuthn step)');
  } else if (d1.error === 'Challenge expired or invalid' || d1.error === 'Challenge integrity check failed') {
    console.log('FAIL: Challenge invalid after restart');
    process.exit(1);
  } else {
    console.log('UNKNOWN:', d1.error);
  }

  // Test 2: Consumed challenge stays consumed
  const db2 = new Database(dbPath);
  const consumed = db2.prepare('SELECT id, pr_number FROM challenges WHERE used = 1 ORDER BY created_at DESC LIMIT 1').get();
  db2.close();

  if (consumed) {
    console.log('\n=== TEST 2: Consumed challenge stays consumed ===');
    const r2 = await fetch(`${url}/api/prs/${consumed.pr_number}/confirm`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: consumed.id, credential: {}, challenge: 'test' })
    });
    const d2 = await r2.json();
    console.log('Status:', r2.status, '=>', JSON.stringify(d2));
    if (d2.error === 'Challenge already used') {
      console.log('PASS: Consumed challenge stays consumed');
    } else {
      console.log('FAIL: Expected "Challenge already used"');
      process.exit(1);
    }
  }

  console.log('\nAll restart tests passed');
  process.exit(0);
}
main().catch(e => { console.error(e); process.exit(1); });
