const https = require('https');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const HOST = '127.0.0.1';
const PORT = 3443;
const SESSION_ID = 'd8e6199d-e852-40a2-8b27-db881c795cf9';
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
      res.on('end', () => resolve({
        status: res.statusCode,
        body: data.slice(0, 300),
        time: Date.now() - start,
        setCookie: res.headers['set-cookie']
      }));
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
    console.log(`${label}: ${r.error || (r.status + ' ' + r.body.slice(0, 120))} [${r.time}ms]`);
  } catch (e) {
    results.push({ label, error: e.message });
    console.log(`${label}: ERROR ${e.message}`);
  }
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('=== SENTINEL ORACLE RED TEAM ATTACK ===\n');

  // === PHASE 1: Recon ===
  console.log('--- PHASE 1: RECON ---');
  await attack('P1. Status (public)', () => req('GET', '/api/status'));
  await attack('P1. Session check (no cookie)', () => req('GET', '/api/session/check'));
  await sleep(200);

  // === PHASE 2: Attempt without auth ===
  console.log('\n--- PHASE 2: UNAUTHENTICATED ATTACKS ---');
  await attack('P2. PR list (no auth)', () => req('GET', '/api/prs'));
  await attack('P2. Lockdown (no auth)', () => req('POST', '/api/lockdown'));
  await attack('P2. Register device (no auth)', () => req('POST', '/api/webauthn/register/begin', { deviceName: 'evil' }));
  await attack('P2. List devices (no auth)', () => req('GET', '/api/devices'));
  await attack('P2. Audit log (no auth)', () => req('GET', '/api/audit'));
  await attack('P2. Authorize PR (no auth)', () => req('POST', '/api/prs/142/authorize'));
  await attack('P2. Reject PR (no auth)', () => req('POST', '/api/prs/142/reject', {}));
  await attack('P2. Revoke device (no auth)', () => req('POST', '/api/devices/fake/revoke'));
  await attack('P2. Unlock (no auth)', () => req('POST', '/api/unlock'));
  await sleep(200);

  // === PHASE 3: With valid session ===
  console.log('\n--- PHASE 3: AUTHENTICATED OPERATIONS ---');
  await attack('P3. PR list (with session)', () => req('GET', '/api/prs', null, SESSION_ID));
  await attack('P3. Authorize PR (with session)', () => req('POST', '/api/prs/142/authorize', null, SESSION_ID));
  await attack('P3. Devices list (with session)', () => req('GET', '/api/devices', null, SESSION_ID));
  await attack('P3. Audit log (with session)', () => req('GET', '/api/audit', null, SESSION_ID));
  await attack('P3. Lockdown (with session)', () => req('POST', '/api/lockdown', null, SESSION_ID));
  await attack('P3. Unlock (with session)', () => req('POST', '/api/unlock', null, SESSION_ID));
  await sleep(200);

  // === PHASE 4: Confirm endpoint (no session required) ===
  console.log('\n--- PHASE 4: CONFIRM ENDPOINT ---');
  
  // Get a real challenge ID from authorize first
  const authResult = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  const challengeId = authResult.body ? (() => { try { return JSON.parse(authResult.body).challengeId } catch { return null } })() : null;
  
  await attack('P4. Confirm with fake data', () => req('POST', '/api/prs/142/confirm', {
    challengeId: 'fake-id', credential: { id: 'fake' }, challenge: 'fake-challenge'
  }));
  
  await attack('P4. Confirm after authorize (no WebAuthn)', () => req('POST', '/api/prs/142/confirm', {
    challengeId, credential: { id: 'fake', response: { authenticatorData: 'aaa', signature: 'bbb' } }, challenge: 'fake-webauthn'
  }));
  
  await attack('P4. Confirm empty credential', () => req('POST', '/api/prs/142/confirm', {
    challengeId, credential: {}, challenge: 'challenge'
  }));
  
  await attack('P4. Confirm null body', () => req('POST', '/api/prs/142/confirm', {
    challengeId: null, credential: null, challenge: null
  }));

  await attack('P4. Confirm invalid PR number', () => req('POST', '/api/prs/NaN/confirm', {
    challengeId: 'x', credential: { id: 'x' }, challenge: 'x'
  }));

  await attack('P4. Confirm negative PR number', () => req('POST', '/api/prs/-1/confirm', {
    challengeId: 'x', credential: { id: 'x' }, challenge: 'x'
  }));

  await attack('P4. Confirm large PR number', () => req('POST', '/api/prs/9999999999/confirm', {
    challengeId: 'x', credential: { id: 'x' }, challenge: 'x'
  }));
  await sleep(200);

  // === PHASE 5: Session attacks ===
  console.log('\n--- PHASE 5: SESSION ATTACKS ---');
  
  await attack('P5. Random session UUID', () => req('GET', '/api/prs', null, uuidv4()));
  await attack('P5. Empty session cookie', () => req('GET', '/api/prs', null, ''));
  
  // Case-variant cookie
  const r5 = await new Promise(res => {
    const start = Date.now();
    const opts = { hostname: HOST, port: PORT, path: '/api/prs', method: 'GET', headers: { 'Cookie': 'SENTINEL_SESSION=' + SESSION_ID }, rejectUnauthorized: false };
    const req2 = https.request(opts, (rsp) => { let d=''; rsp.on('data',c=>d+=c); rsp.on('end',()=>res({status:rsp.statusCode, body:d.slice(0,200), time: Date.now()-start})); });
    req2.on('error', e => res({error: e.message}));
    req2.end();
  });
  results.push({ label: 'P5. Case-variant cookie', ...r5 });
  console.log(`P5. Case-variant cookie: ${r5.error || (r5.status + ' ' + r5.body.slice(0, 120))} [${r5.time}ms]`);

  await attack('P5. SQL injection in cookie', () => req('GET', '/api/prs', null, "'; DELETE FROM sessions; --"));
  await attack('P5. Long session ID', () => req('GET', '/api/prs', null, 'a'.repeat(10000)));
  await sleep(200);

  // === PHASE 6: Challenge replay ===
  console.log('\n--- PHASE 6: CHALLENGE REPLAY ---');
  
  const authResult2 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  const challengeId2 = authResult2.body ? (() => { try { return JSON.parse(authResult2.body).challengeId } catch { return null } })() : null;
  
  if (challengeId2) {
    await attack('P6. Consume challenge (attempt 1)', () => req('POST', '/api/prs/142/confirm', {
      challengeId: challengeId2, credential: { id: 'test' }, challenge: 'test'
    }));
    await attack('P6. Replay consumed challenge (attempt 2)', () => req('POST', '/api/prs/142/confirm', {
      challengeId: challengeId2, credential: { id: 'test' }, challenge: 'test'
    }));
  }
  await sleep(200);

  // === PHASE 7: Rate limiting ===
  console.log('\n--- PHASE 7: RATE LIMIT ---');
  const rateResults = [];
  for (let i = 0; i < 10; i++) {
    const r = await req('POST', '/api/lockdown', null, SESSION_ID);
    rateResults.push(`${r.status}[${r.time}ms]`);
    await sleep(50);
  }
  console.log(`P7. Rate limit burst (10x lockdown): ${rateResults.join(', ')}`);

  // === PHASE 8: Race conditions ===
  console.log('\n--- PHASE 8: RACE CONDITIONS ---');
  
  const authResult3 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  const challengeId3 = authResult3.body ? (() => { try { return JSON.parse(authResult3.body).challengeId } catch { return null } })() : null;
  
  if (challengeId3) {
    const raceResults = await Promise.all([
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'a' }, challenge: 'a' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'b' }, challenge: 'b' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'c' }, challenge: 'c' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'd' }, challenge: 'd' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'e' }, challenge: 'e' }),
    ]);
    raceResults.forEach((r, i) => {
      console.log(`P8. Race attempt ${i+1}: ${r.status} ${r.body.slice(0,80)} [${r.time}ms]`);
    });
  }
  
  // Lockdown vs confirm race
  console.log('\n--- P8. Lockdown vs Confirm race ---');
  const authResult4 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  const challengeId4 = authResult4.body ? (() => { try { return JSON.parse(authResult4.body).challengeId } catch { return null } })() : null;
  if (challengeId4) {
    await Promise.all([
      req('POST', '/api/lockdown', null, SESSION_ID),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId4, credential: { id: 'race' }, challenge: 'race' }),
    ]);
    console.log('P8. Lockdown+confirm race completed');
    const prStatus = await req('GET', '/api/prs', null, SESSION_ID);
    console.log(`P8. PR status after race: ${prStatus.body.slice(0,200)}`);
  }
  await sleep(200);

  // === PHASE 9: Tamper ===
  console.log('\n--- PHASE 9: TAMPER ---');
  
  await attack('P9. Setup/begin (should be 403)', () => req('POST', '/api/setup/begin', { enrollmentToken: 'test', deviceName: 'hacker' }));
  await attack('P9. Setup/complete (should be 403)', () => req('POST', '/api/setup/complete', { enrollmentToken: 'test', credential: {}, challenge: 'test', deviceName: 'hacker' }));

  // Try SQL injection in PR number param
  await attack('P9. SQL injection in PR number', () => req('POST', '/api/prs/1; DROP TABLE pending_prs; --/authorize', null, SESSION_ID));
  
  // Try prototype pollution
  await attack('P9. Prototype pollution in body', () => req('POST', '/api/prs/142/confirm', { '__proto__': { 'isAdmin': true }, challengeId: 'x', credential: { id: 'x' }, challenge: 'x' }));

  // === SUMMARY ===
  console.log('\n\n========== ATTACK SUMMARY ==========');
  const byStatus = {};
  for (const r of results) {
    const key = r.error ? 'ERROR' : (r.status < 300 ? 'PASS' : r.status < 500 ? 'BLOCKED' : 'OTHER');
    if (!byStatus[key]) byStatus[key] = [];
    byStatus[key].push(`${r.label}: ${r.error || r.status} [${r.time}ms]`);
  }
  for (const [status, items] of Object.entries(byStatus)) {
    console.log(`\n--- ${status} (${items.length}) ---`);
    items.forEach(i => console.log(`  ${i}`));
  }
  
  const blocked = results.filter(r => !r.error && r.status === 401).length;
  const passedAuth = results.filter(r => !r.error && r.status < 300 && r.label.includes('P3')).length;
  const passedPublic = results.filter(r => !r.error && r.status < 300 && (r.label.includes('P1') || r.label.includes('public'))).length;
  const all401 = results.filter(r => !r.error && r.status === 401).length;
  const all200 = results.filter(r => !r.error && r.status === 200).length;
  const all400 = results.filter(r => !r.error && r.status === 400).length;
  const all403 = results.filter(r => !r.error && r.status === 403).length;
  const all423 = results.filter(r => !r.error && r.status === 423).length;
  const errors = results.filter(r => r.error).length;
  
  console.log(`\nTOTAL ATTACKS: ${results.length}`);
  console.log(`  200 (OK):     ${all200}`);
  console.log(`  400 (BadReq): ${all400}`);
  console.log(`  401 (NoAuth): ${all401}`);
  console.log(`  403 (Forbid): ${all403}`);
  console.log(`  423 (Locked): ${all423}`);
  console.log(`  ERRORS:       ${errors}`);
  console.log(`\nCONCLUSION: ${all401 + all403 > results.length * 0.5 ? 'SECURE' : 'VULNERABILITIES DETECTED'}`);
  console.log(`Blocked rate: ${((all401 + all403 + all423) / Math.max(1, results.length - errors) * 100).toFixed(0)}%`);
}

main().catch(console.error);
