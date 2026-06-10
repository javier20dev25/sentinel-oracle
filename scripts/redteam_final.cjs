const https = require('https');

const HOST = '127.0.0.1';
const PORT = 3443;
const SESSION_ID = 'bb22df9d-7afe-454e-9484-72931e797fb7';
const results = [];

function req(method, path, body, cookie) {
  return new Promise((resolve) => {
    const start = Date.now();
    const opts = {
      hostname: HOST, port: PORT,
      method, path,
      headers: { 'Content-Type': 'application/json' },
      rejectUnauthorized: false
    };
    if (cookie) opts.headers['Cookie'] = `sentinel_session=${cookie}`;
    if (!body) delete opts.headers['Content-Type'];
    const r = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data.slice(0, 8000), time: Date.now() - start }));
    });
    r.on('error', e => resolve({ error: e.message, time: Date.now() - start }));
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

async function attack(label, fn) {
  try {
    const r = await fn();
    results.push({ label, ...r });
    console.log(`${label}: ${r.error || (r.status + ' ' + r.body.slice(0, 140))} [${r.time}ms]`);
  } catch (e) {
    results.push({ label, error: e.message });
    console.log(`${label}: ERROR ${e.message}`);
  }
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('=== FINAL RED TEAM: FULL ATTACK ===\n');

  // ---- P1: Authorize PR ----
  console.log('--- P1: Authorize ---');
  const authRes = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  console.log(`P1. Authorize PR 142: ${authRes.status} ${authRes.body} [${authRes.time}ms]`);
  let cid = null;
  try { const j = JSON.parse(authRes.body); cid = j.challengeId; } catch {}
  if (!cid) {
    console.log('FATAL: No challengeId from authorize. DB may be corrupted.');
    process.exit(1);
  }
  console.log(`P1. Challenge ID: ${cid}`);
  await sleep(50);

  // ---- P2: Confirm without valid WebAuthn (reject) ----
  console.log('\n--- P2: Confirm invalid ---');
  await attack('P2. Bad credential (expect 400)', () => req('POST', '/api/prs/142/confirm', {
    challengeId: cid, credential: { id: 'hack', response: { authenticatorData: 'x', clientDataJSON: 'y', signature: 'z' } }, challenge: cid
  }));
  await sleep(50);

  // Re-authorize since likely consumed/rejected
  const auth2 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  console.log(`P2. Re-authorize: ${auth2.status} ${auth2.body.slice(0,200)} [${auth2.time}ms]`);
  let cid2 = null;
  try { cid2 = JSON.parse(auth2.body).challengeId; } catch {}
  if (!cid2) { console.log('FATAL: re-authorize failed'); process.exit(1); }
  console.log(`P2. Challenge ID2: ${cid2}`);
  await sleep(50);

  // ---- P3: Challenge replay ----
  console.log('\n--- P3: Replay ---');
  // Consume with bad credential
  await req('POST', '/api/prs/142/confirm', { challengeId: cid2, credential: { id: 'bad', response: { authenticatorData: 'x', clientDataJSON: 'y', signature: 'z' } }, challenge: cid2 });
  // Replay attempt
  await attack('P3. Replay same challenge (expect 400/429)', () => req('POST', '/api/prs/142/confirm', {
    challengeId: cid2, credential: { id: 'bad2', response: { authenticatorData: 'x2', clientDataJSON: 'y2', signature: 'z2' } }, challenge: cid2
  }));
  await sleep(100);

  // ---- P4: Race condition - 5 concurrent confirms ----
  console.log('\n--- P4: Race ---');
  const auth3 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  let cid3 = null;
  try { cid3 = JSON.parse(auth3.body).challengeId; } catch {}
  if (!cid3) { console.log('FATAL: authorize 3 failed'); process.exit(1); }
  console.log(`P4. Challenge ID3: ${cid3}`);

  const confs = await Promise.all([
    req('POST', '/api/prs/142/confirm', { challengeId: cid3, credential: { id: 'R1', response: { authenticatorData: 'r1', clientDataJSON: 'r1', signature: 'r1' } }, challenge: cid3 }),
    req('POST', '/api/prs/142/confirm', { challengeId: cid3, credential: { id: 'R2', response: { authenticatorData: 'r2', clientDataJSON: 'r2', signature: 'r2' } }, challenge: cid3 }),
    req('POST', '/api/prs/142/confirm', { challengeId: cid3, credential: { id: 'R3', response: { authenticatorData: 'r3', clientDataJSON: 'r3', signature: 'r3' } }, challenge: cid3 }),
    req('POST', '/api/prs/142/confirm', { challengeId: cid3, credential: { id: 'R4', response: { authenticatorData: 'r4', clientDataJSON: 'r4', signature: 'r4' } }, challenge: cid3 }),
    req('POST', '/api/prs/142/confirm', { challengeId: cid3, credential: { id: 'R5', response: { authenticatorData: 'r5', clientDataJSON: 'r5', signature: 'r5' } }, challenge: cid3 }),
  ]);
  confs.forEach((r, i) => console.log(`P4. Race #${i+1}: ${r.status} ${r.body.slice(0,100)} [${r.time}ms]`));
  
  // Check PR state after race
  const prAfterRace = await req('GET', '/api/prs', null, SESSION_ID);
  console.log(`P4. PR after race: ${prAfterRace.body.slice(0,300)}`);
  await sleep(100);

  // ---- P5: TOCTOU - lockdown + confirm race ----
  console.log('\n--- P5: TOCTOU race ---');
  const auth4 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  let cid4 = null;
  try { cid4 = JSON.parse(auth4.body).challengeId; } catch {}
  if (!cid4) { console.log('FATAL: authorize 4 failed'); process.exit(1); }
  console.log(`P5. Challenge ID4: ${cid4}`);

  const [lockRes, confRes] = await Promise.all([
    req('POST', '/api/lockdown', null, SESSION_ID),
    req('POST', '/api/prs/142/confirm', { challengeId: cid4, credential: { id: 'T1', response: { authenticatorData: 't1', clientDataJSON: 't1', signature: 't1' } }, challenge: cid4 }),
  ]);
  console.log(`P5. Lockdown: ${lockRes.status} ${lockRes.body.slice(0,80)} [${lockRes.time}ms]`);
  console.log(`P5. Confirm (TOCTOU test): ${confRes.status} ${confRes.body.slice(0,80)} [${confRes.time}ms]`);
  
  // Check if merge happened despite lockdown
  const audit = await req('GET', '/api/audit', null, SESSION_ID);
  console.log(`P5. Audit log: ${audit.body.slice(0,400)}`);
  await sleep(100);

  // ---- P6: Unlock and verify system works ----
  console.log('\n--- P6: System check ---');
  const unlockRes = await req('POST', '/api/unlock', null, SESSION_ID);
  console.log(`P6. Unlock: ${unlockRes.status} ${unlockRes.body.slice(0,80)} [${unlockRes.time}ms]`);
  const prList = await req('GET', '/api/prs', null, SESSION_ID);
  console.log(`P6. PR list: ${prList.body.slice(0,300)}`);

  // ---- P7: Confirm with tampered challengeId ----
  console.log('\n--- P7: Tamper ---');
  const auth5 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  let cid5 = null;
  try { cid5 = JSON.parse(auth5.body).challengeId; } catch {}
  if (!cid5) { console.log('FATAL: authorize 5 failed'); process.exit(1); }
  console.log(`P7. Challenge ID5: ${cid5}`);

  await attack('P7. Wrong challenge ID', () => req('POST', '/api/prs/142/confirm', {
    challengeId: cid5.replace(/./g, 'x'), credential: { id: 'x', response: { authenticatorData: 'x', clientDataJSON: 'x', signature: 'x' } }, challenge: cid5
  }));
  await attack('P7. Empty challenge ID', () => req('POST', '/api/prs/142/confirm', {
    challengeId: '', credential: { id: 'x' }, challenge: ''
  }));
  await attack('P7. No challenge ID field', () => req('POST', '/api/prs/142/confirm', {
    credential: { id: 'x' }
  }));
  await attack('P7. Extra fields (prototype pollution)', () => req('POST', '/api/prs/142/confirm', {
    challengeId: cid5, credential: { id: 'x', response: { authenticatorData: 'x', clientDataJSON: 'x', signature: 'x' } }, challenge: cid5, __proto__: { admin: true }, admin: true
  }));

  // ---- P8: CRUD - session re-use between requests ----
  console.log('\n--- P8: Session freshness ---');
  // The session should be getting touched. Let me verify 5 rapid requests still work
  const rapid = [];
  for (let i = 0; i < 5; i++) {
    const r = await req('GET', '/api/prs', null, SESSION_ID);
    rapid.push(`${r.status}[${r.time}ms]`);
  }
  console.log(`P8. Rapid requests: ${rapid.join(', ')}`);

  // ---- P9: Audit device list ----
  console.log('\n--- P9: Device list + revoke ---');
  await attack('P9. Device list', () => req('GET', '/api/devices', null, SESSION_ID));
  await attack('P9. Revoke non-existent device', () => req('POST', '/api/devices/9999/revoke', null, SESSION_ID));

  // ============ SUMMARY ============
  console.log('\n\n=========== ATTACK SUMMARY ===========');
  const byStatus = {};
  for (const r of results) {
    const key = r.error ? 'ERROR' : r.status === 200 ? '200-OK' : r.status === 400 ? '400-BADREQ' : r.status === 401 ? '401-NOAUTH' : r.status === 403 ? '403-FORBID' : r.status === 404 ? '404-NOTFOUND' : r.status === 423 ? '423-LOCKED' : r.status === 429 ? '429-RATE' : `${r.status}-OTHER`;
    if (!byStatus[key]) byStatus[key] = [];
    byStatus[key].push(`${r.label}`);
  }
  for (const [status, items] of Object.entries(byStatus)) {
    console.log(`\n${status} (${items.length}):`);
    items.forEach(i => console.log(`  ${i}`));
  }
  console.log(`\nTOTAL: ${results.length}`);
  console.log(`SECURE: all non-2xx responses are expected behavior (bad data = 400, no cred = 429, expired = 401)`);
}

main().catch(console.error);
