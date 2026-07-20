# Sentinel Oracle — Security Audit Report

## Threat Model

```
Workstation (untrusted) → Oracle Server (trusted authority) → Phone (identity proof)
```

The Oracle assumes the **workstation is compromised**. It does not trust the developer's machine.
Merge authority lives on a physically separate server. The phone provides biometric proof
bound to a specific PR.

---

## Protection Layers

### 1. Authentication (WebAuthn / Passkeys)

| Property | Status |
|----------|--------|
| Phishing-resistant | Yes — origin-bound credentials |
| Per-authorization assertion | Yes — fresh assertion per PR, not just login |
| Credential ID bound to PR | Yes — in assertion challenge |
| Device revocation | Yes — revoke removes credential_id from DB |
| Attestation | Not verified — privacy concern, CA agreement |

**Why it matters**: Passkeys cannot be phished. Even if an attacker controls the
network (DNS, proxy, etc.), the WebAuthn assertion validates the Relying Party origin.
Each merge requires a fresh biometric prompt on the phone.

---

### 2. Challenge Integrity (QR Code Flow)

| Property | Status |
|----------|--------|
| HMAC-signed payload | Yes — SHA-256 HMAC before WebAuthn |
| Atomic consumption | Yes — `UPDATE ... WHERE used = 0` |
| Single-PR binding | Yes — challenge stores pr_number |
| TTL enforcement | Yes — 45s max (configurable) |
| Replay protection | Yes — consumed flag prevents double-use |

**Why it matters**: The QR code is signed so it cannot be forged or tampered with
(attacker cannot redirect the phone to authorize a different PR). Atomic consumption
ensures the first caller wins — even if the QR code is intercepted and used by two
phones simultaneously, only one succeeds.

---

### 3. TOCTOU Prevention (Time-of-Check, Time-of-Use)

| Property | Status |
|----------|--------|
| Lockdown re-checked after WebAuthn | Yes — `isLocked()` called again before merge |
| Challenge consumed before merge | Yes — consumed before lockdown check |
| Atomic operations | Yes — SQLite transactions |

**Why it matters**: Between verifying the biometric and executing the merge, an
administrator might activate lockdown. The re-check ensures the merge is blocked
even if the biometric passed milliseconds earlier.

---

### 4. Session Management

| Property | Status |
|----------|--------|
| Cookie flags | HttpOnly + Secure + SameSite=Strict |
| Session TTL | 24h absolute + 30min idle timeout |
| Signed cookie | Yes — cookieParser(encryptionKey) |
| Session storage | SQLite (server-side, not in cookie) |

**Why it matters**: The session cookie cannot be read by JavaScript (HttpOnly),
cannot be exfiltrated over HTTP (Secure), and cannot be sent cross-site (SameSite).
Idle timeout limits exposure from unattended sessions.

---

### 5. Rate Limiting

| Property | Status |
|----------|--------|
| Auth endpoints | 5 requests / 60s window |
| API endpoints | 30 requests / 60s window |
| Trust proxy | Yes — `app.set('trust proxy', 1)` for Tailscale Funnel |

**Why it matters**: Brute-force attacks against the session or authorization
endpoints are throttled. The rate limiter respects X-Forwarded-For behind Funnel.

---

### 6. Encryption at Rest

| Property | Status |
|----------|--------|
| Device public keys | AES-256-GCM encrypted in SQLite |
| Challenge data | AES-256-GCM encrypted in SQLite |
| Encryption key derivation | 32-byte random, stored in `.encryption_key` (mode 0600) |
| DB file itself | Not encrypted — relies on filesystem permissions |

**Limitation**: The encryption key is on disk. An attacker with root access can
read it. TPM/HSM binding is planned for a later phase.

---

### 7. Network Security

| Property | Status |
|----------|--------|
| TLS | Yes — self-signed cert or Let's Encrypt via Tailscale Funnel |
| No open firewall ports | Yes — Tailscale Funnel outbound-only |
| CORS blocked | Yes — all non-origin requests rejected |
| Security headers | helmet middleware active |
| X-Forwarded-For trusted | Yes — for Tailscale Funnel proxy |

**Why it matters**: No ports need to be opened on the firewall. Tailscale Funnel
provides Let's Encrypt TLS via outbound connection to Tailscale edge. The server
is unreachable from the public internet except through the Funnel URL (random hash
on *.ts.net).

---

### 8. Merge Authority Isolation

| Property | Status |
|----------|--------|
| Merge API called by Oracle only | Yes — workstation never holds the token |
| PAT scope | Fine-grained or classic, minimal repo permissions |
| Status check required | Yes — `Sentinel Authorization` context |
| Branch protection | Relies on GitHub branch protection rules enforced server-side |

**Why it matters**: The workstation initiates authorization but cannot execute the
merge. Only the Oracle server, after biometric verification, calls `pulls.merge()`.
Even if the workstation is fully compromised, the attacker cannot merge without
the phone.

---

### 9. New: Enrollment Password (Second Factor)

| Property | Status |
|----------|--------|
| Password hashing | scrypt (Node.js crypto.scryptSync) |
| Storage | Only the bcrypt-like hash (`salt:key`) in config.json |
| Verification | Timing-safe comparison |
| Optional | Yes — skipped if passwordHash is empty |
| Changeable | Yes — via Dashboard (requires current password) |

**Why it matters**: If an attacker gains access to the Oracle server and reads the
GitHub PAT from config.json, they still cannot authorize a merge without the
enrollment password. This adds an out-of-band factor: the password must be known
to the authorized operator, not just stored on the server.

---

### 10. Enrollment Token Rotation

| Property | Status |
|----------|--------|
| Auto-refresh | Yes — every 2 minutes (configurable) |
| In-memory only | Not written to disk after refresh |
| One-time use | Consumed after first successful enrollment |

**Why it matters**: If the enrollment token is exposed (e.g., screenshot of the
terminal), the window of exploitation is limited to the refresh interval (2 min).
The token is never persisted after the initial write.

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Server compromise (root) | Low | Critical | Enrollment password, encryption at rest, no PAT in memory after use |
| GitHub PAT theft | Low | High | Enrollment password + branch protection + status checks |
| Phone theft | Low | Low | Device revoked immediately, biometric lock on phone |
| QR code interception | Low | Medium | HMAC + atomic consumption + 45s TTL + PR binding |
| Network MITM | Low | Medium | TLS + WebAuthn origin validation |
| CSRF / XSS | Low | Low | SameSite=Strict + HttpOnly cookies + CSP |
| SQL injection | Very Low | Low | Parameterized queries (better-sqlite3) |
| DoS (rate limit bypass) | Medium | Low | Rate limiting per IP + Funnel DDoS protection |

---

## Conclusion

The Sentinel Oracle implements **defense in depth** across authentication, integrity,
network, storage, and operational security. The architectural decision to physically
isolate merge authority is the strongest protection: even a fully compromised
workstation cannot merge code without a biometric proof from the phone and now
(optionally) an enrollment password known only to the operator.

**Remaining attack surface** (accepted risks):
- Root compromise of the Oracle server exposes the GitHub PAT and encryption key
- No TPM/HSM binding (planned for a later phase)
- Self-signed TLS certs when not using Tailscale Funnel (browser warnings)
- No GitHub App integration (JWT per-installation tokens would reduce PAT exposure)
- No approval delay / multi-signer requirement (future enhancement)

The current architecture is **secure for MVP deployment** against the stated threat
model (workstation untrusted, server and phone trusted). The enrollment password
closes the highest-severity residual risk (stolen PAT via server compromise) by
requiring an out-of-band factor.
