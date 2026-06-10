const https = require('https');

const HOST = '127.0.0.1';
const PORT = 3443;
const SESSION_ID = '6df0d416-33e5-484a-9e40-17339f0467c8';
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
        body: data.slice(0, 400),
        time: Date.now() - start,
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
    let statusInfo = r.error ? `ERROR ${r.error}` : `${r.status} ${r.body.slice(0,150)}`;
    console.log(`${label}: ${statusInfo} [${r.time}ms]`);
  } catch (e) {
    results.push({ label, error: e.message });
    console.log(`${label}: ERROR ${e.message}`);
  }
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('=== FOCUSED RED TEAM: AUTH + REPLAY + RACE ===\n');

  // == Phase 1: Verify fresh session works ==
  console.log('--- P1: Session verification ---');
  await attack('P1. PR list (fresh session)', () => req('GET', '/api/prs', null, SESSION_ID));
  await attack('P1. Devices list (fresh session)', () => req('GET', '/api/devices', null, SESSION_ID));
  await attack('P1. Lockdown (fresh session)', () => req('POST', '/api/lockdown', null, SESSION_ID));
  await attack('P1. Unlock (fresh session)', () => req('POST', '/api/unlock', null, SESSION_ID));
  await sleep(200);

  // == Phase 2: Authorize PR ==
  console.log('\n--- P2: Authorize PR ---');
  const authRes = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  console.log(`P2. Authorize PR: ${authRes.status} ${authRes.body} [${authRes.time}ms]`);
  
  let challengeId = null;
  try { challengeId = JSON.parse(authRes.body).challengeId; } catch {}
  
  // == Phase 3: Challenge replay ==
  console.log('\n--- P3: Challenge replay ---');
  if (challengeId) {
    console.log(`  Challenge ID: ${challengeId}`);
    console.log(`  HMAC: ${JSON.parse(authRes.body).hmac ? 'present' : 'missing'}`);
    console.log(`  QR URL: ${JSON.parse(authRes.body).qrUrl || 'N/A'}`);
    
    // Attempt 1 (will fail because HMAC not signed properly)
    await attack('P3. Confirm attempt 1 (bad HMAC)', () => req('POST', `/api/prs/142/confirm`, {
      challengeId, credential: { id: 'test', response: { authenticatorData: 'aaa', clientDataJSON: 'bbb', signature: 'ccc', userHandle: null } }, challenge: 'wrong-hmac'
    }));
    
    // Attempt 2 (replay)
    await attack('P3. Confirm attempt 2 (replay)', () => req('POST', `/api/prs/142/confirm`, {
      challengeId, credential: { id: 'test', response: { authenticatorData: 'aaa', clientDataJSON: 'bbb', signature: 'ccc', userHandle: null } }, challenge: 'wrong-hmac'
    }));
    
    // Check if still available
    const checkRes = await req('POST', `/api/prs/142/confirm`, {
      challengeId, credential: { id: 'test2', response: { authenticatorData: 'ddd', clientDataJSON: 'eee', signature: 'fff', userHandle: null } }, challenge: 'other-hmac'
    });
    console.log(`P3. Confirm attempt 3 (different data): ${checkRes.status} ${checkRes.body.slice(0,150)} [${checkRes.time}ms]`);
  }
  await sleep(200);

  // == Phase 4: Lockdown bypass attempts ==
  console.log('\n--- P4: Lockdown bypass ---');
  // Lock down
  await attack('P4. Lock system', () => req('POST', '/api/lockdown', null, SESSION_ID));
  // Try to authorize while locked
  await attack('P4. Authorize while locked', () => req('POST', '/api/prs/142/authorize', null, SESSION_ID));
  // Try to confirm while locked
  await attack('P4. Confirm while locked (no challenge)', () => req('POST', '/api/prs/142/confirm', {
    challengeId: 'x', credential: { id: 'x' }, challenge: 'x'
  }));
  // Unlock
  await attack('P4. Unlock system', () => req('POST', '/api/unlock', null, SESSION_ID));
  await sleep(200);

  // == Phase 5: Authorize + race confirm vs lockdown ==
  console.log('\n--- P5: Race condition authorize+confirm vs lockdown ---');
  
  // Re-authorize after unlock
  const authRes2 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  let challengeId2 = null;
  try { challengeId2 = JSON.parse(authRes2.body).challengeId; } catch {}
  
  if (challengeId2) {
    console.log(`  Challenge ID: ${challengeId2}`);
    
    // Fire lockdown + confirm concurrently
    const raceStart = Date.now();
    const [lockR, confR] = await Promise.all([
      req('POST', '/api/lockdown', null, SESSION_ID),
      req('POST', '/api/prs/142/confirm', {
        challengeId: challengeId2, credential: { id: 'race', response: { authenticatorData: 'race', clientDataJSON: 'race', signature: 'race', userHandle: null } }, challenge: 'race-hmac'
      })
    ]);
    console.log(`P5. Lockdown: ${lockR.status} ${lockR.body.slice(0,100)} [${lockR.time}ms]`);
    console.log(`P5. Confirm: ${confR.status} ${confR.body.slice(0,100)} [${confR.time}ms]`);
    console.log(`P5. Race total: ${Date.now() - raceStart}ms`);
    
    // Check PR status
    const prRes = await req('GET', '/api/prs', null, SESSION_ID);
    console.log(`P5. PR status after race: ${prRes.body.slice(0,300)}`);
    
    // was the merge executed? Check audit log
    const auditRes = await req('GET', '/api/audit', null, SESSION_ID);
    console.log(`P5. Audit: ${auditRes.body.slice(0,300)}`);
  }
  await sleep(200);

  // == Phase 6: Multiple concurrent confirms ==
  console.log('\n--- P6: Concurrent confirm race ---');
  // Unlock first
  await req('POST', '/api/unlock', null, SESSION_ID);
  
  const authRes3 = await req('POST', '/api/prs/142/authorize', null, SESSION_ID);
  let challengeId3 = null;
  try { challengeId3 = JSON.parse(authRes3.body).challengeId; } catch {}
  
  if (challengeId3) {
    console.log(`  Challenge ID: ${challengeId3}`);
    const confs = await Promise.all([
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'a', response: { authenticatorData: 'a1', clientDataJSON: 'a2', signature: 'a3', userHandle: null } }, challenge: 'a-hmac' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'b', response: { authenticatorData: 'b1', clientDataJSON: 'b2', signature: 'b3', userHandle: null } }, challenge: 'b-hmac' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'c', response: { authenticatorData: 'c1', clientDataJSON: 'c2', signature: 'c3', userHandle: null } }, challenge: 'c-hmac' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'd', response: { authenticatorData: 'd1', clientDataJSON: 'd2', signature: 'd3', userHandle: null } }, challenge: 'd-hmac' }),
      req('POST', '/api/prs/142/confirm', { challengeId: challengeId3, credential: { id: 'e', response: { authenticatorData: 'e1', clientDataJSON: 'e2', signature: 'e3', userHandle: null } }, challenge: 'e-hmac' }),
    ]);
    confs.forEach((r, i) => {
      console.log(`P6. Confirm #${i+1}: ${r.status} ${r.body.slice(0,120)} [${r.time}ms]`);
    });
    
    const prRes2 = await req('GET', '/api/prs', null, SESSION_ID);
    console.log(`P6. PR status after race: ${prRes2.body.slice(0,300)}`);
    
    const auditRes2 = await req('GET', '/api/audit', null, SESSION_ID);
    console.log(`P6. Audit: ${auditRes2.body.slice(0,400)}`);
  }
  await sleep(200);

  // == Phase 7: TOCTOU verification ==
  // Check that isLocked() is re-checked after WebAuthn verification
  // The TOCTOU fix in authorization.ts should catch this
  console.log('\n--- P7: Previously fixed TOCTOU check ---');
  // Already tested in P5 (lockdown + confirm race), but let's verify
  console.log('P7. TOCTOU tested in P5 - verify lockdown status before merge confirmed');

  // == Phase 8: Session manipulation ==
  console.log('\n--- P8: Session attacks ---');
  // SQL injection via cookie
  await attack('P8. SQL injection UPDATE', () => req('GET', '/api/prs', null, "' UNION SELECT * FROM auth_devices; --"));
  await attack('P8. SQL in session check', () => req('GET', '/api/session/check', null, "' OR 1=1; --"));
  
  // XSS in device name
  await attack('P8. XSS in PR title (via query param)', () => req('GET', '/api/prs/<script>alert(1)</script>', null, SESSION_ID));

  // == SUMMARY ==
  console.log('\n\n========== ATTACK SUMMARY ==========');
  const byStatus = {};
  for (const r of results) {
    const key = r.error ? 'ERROR' : (r.status < 300 ? '200-OK' : r.status === 400 ? '400-BAD' : r.status === 401 ? '401-NO' : r.status === 403 ? '403-FOR' : r.status === 423 ? '423-LOCK' : r.status === 429 ? '429-RATE' : `${r.status}-OTHER`);
    if (!byStatus[key]) byStatus[key] = [];
    byStatus[key].push(`${r.label}: ${r.error || r.status} [${r.time}ms]`);
  }
  for (const [status, items] of Object.entries(byStatus)) {
    console.log(`\n${status} (${items.length}):`);
    items.forEach(i => console.log(`  ${i}`));
  }
  
  const authdOK = results.filter(r => !r.error && r.status === 200 && r.label.startsWith('P1.')).length;
  const blocked = results.filter(r => !r.error && (r.status === 401 || r.status === 403 || r.status === 423 || r.status === 429)).length;
  const total = results.filter(r => !r.error).length;
  console.log(`\nTOTAL: ${total} | Auth OK: ${authdOK} | Blocked(401/403/423/429): ${blocked} | Block rate: ${(blocked/Math.max(1,total)*100).toFixed(0)}%`);
}

main().catch(console.error);
