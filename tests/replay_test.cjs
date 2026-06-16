// Replay attack test: try to reuse a consumed challenge
// Run: node tests/replay_test.cjs
const url = 'https://desktop-ki5app4.tail35419a.ts.net';

async function main() {
  // First, get a consumed challenge from the DB
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

  const body = JSON.stringify({
    challengeId: consumed.id,
    credential: {},
    challenge: 'deadbeef',
    reason: 'Replay test'
  });

  const res = await fetch(`${url}/api/prs/${consumed.pr_number}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  });
  const data = await res.json();

  console.log('Status:', res.status, '=>', JSON.stringify(data));

  if (data.error === 'Challenge already used') {
    console.log('PASS: Replay correctly rejected');
    process.exit(0);
  } else {
    console.log('FAIL: Expected "Challenge already used"');
    process.exit(1);
  }
}
main().catch(e => { console.error(e); process.exit(1); });
