// Replay attack test: try to reuse a consumed challenge
// Run: node tests/replay_test.cjs
const https = require('https');
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

async function main() {
  const Database = require('better-sqlite3');
  const path = require('path');
  const os = require('os');
  const db = new Database(path.join(os.homedir(), '.sentinel-oracle/oracle.db'));
  const consumed = db.prepare('SELECT id, pr_number FROM challenges WHERE used = 1 ORDER BY created_at DESC LIMIT 1').get();
  db.close();

  if (!consumed) {
    console.log('FAIL: No consumed challenge found in DB');
    process.exit(1);
  }

  console.log('=== REPLAY TEST ===');
  console.log('Challenge:', consumed.id, 'PR:', consumed.pr_number);

  const r = await post(`/api/prs/${consumed.pr_number}/confirm`, {
    challengeId: consumed.id,
    credential: {},
    challenge: 'deadbeef',
    reason: 'Replay test'
  });

  console.log('Status:', r.status, '=>', JSON.stringify(r.body));

  if (r.body.error === 'Challenge already used') {
    console.log('PASS: Replay correctly rejected');
    process.exit(0);
  } else {
    console.log('FAIL: Expected "Challenge already used"');
    process.exit(1);
  }
}
main().catch(e => { console.error(e); process.exit(1); });
