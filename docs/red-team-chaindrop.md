# Red Team: ChainDrop / Shai-Hulud (npm supply-chain worm)

Incident: **Aug 4 2026** — the npm registry was hit by a self-propagating worm
published from the compromised GitHub account of maintainer **jaredwray**. Malicious
versions (e.g. `keyv@6.0.0`) shipped a `preinstall: node setup.mjs` lifecycle hook, a
~30KB dropper (`setup.mjs`) and an obfuscated bundle (`Math_Symbol.js`, ~700KB). The
worm auto-installed as a transitive dependency and republished more malicious
versions, which were later **depublished** (404 on the registry).

This document records how each Sentinel product behaved **before** and **after** the
improvements, and how the scenario was verified.

---

## The two detection axes

1. **Package content is present** (a tarball was extracted / files are on disk).
2. **A consumer just adds `keyv@^6.0.0` to a manifest** — the PR only shows a line of
   text; the malicious tarball content is invisible to a diff.

Axis 2 is the real attack: **a manifest line is never the payload**. Detecting it
requires going to the registry and inspecting the actual published artifact.

## Before the improvements

| Scenario | Cloud | CLI | Oracle |
|----------|-------|-----|--------|
| Malicious tarball content on disk / in PR | 178 CRITICAL (LiteScanner-grade) | 11 findings, exit 1 | 6 findings / riskScore 39 |
| Consumer adds `keyv@^6.0.0` (manifest only) | 0 findings | `findings: []`, exit 0 — **skips `node_modules` silently** | riskScore 0 — no REVIEW, no attestation |

All three caught the payload once its **content** was visible; none could reason
about the **manifest-only** case, and the CLI never disclosed that it was skipping
installed packages.

## After the improvements

| Product | Improvement | Manifest-only `keyv@^6.0.0` now |
|---------|-------------|----------------------------------|
| **Cloud** | Registry Manifest Intelligence (`registry_manifest.ts`) — evolution signals: new/changed lifecycle hooks, new bins, direct-URL deps, significant growth, deployment-target change; dependency reputation cache per exact version | Evolution/heuristic signals flagged; live red team: 7 probes, 1 legitimate WARNING (`file-entry-cache@8.0.0` engines change), **0 false positives**; `keyv@^6.0.0` unresolvable degrades gracefully |
| **CLI** | `scan --audit-node-modules` + coverage disclosure (`mode: source_only` + warning) + signed `verify-pkg` tarball scan with lifecycle hooks + deep-audit hint | Default scan now **discloses the blind spot**; `--audit-node-modules` catches the installed payload (11 findings, exit 1); `verify-pkg keyv` returns signed tarball analysis |
| **Oracle** | `REVIEW` verdict for added/updated deps + HMAC-signed attestation + **tarball scan of added deps** (findings folded into verdict/attestation) | PR consumer becomes **REVIEW** (unverified dep) → **BLOCK** when the registry serves the malicious tarball (critical lifecycle + shell findings) → `HIGH` "version not published" when depublished |

### Oracle chain for the manifest-only case (after #4 + #5)

1. PR adds `"keyv": "^6.0.0"` → `determineScanVerdict` → **REVIEW** ("dependency
   added, not independently verified").
2. Tarball scan resolves the version against the registry:
   - registry still serves `6.0.0` → tarball downloaded; `preinstall: node setup.mjs`
     → **critical** `Dangerous lifecycle script`, Shell capability → **critical**;
     `eval()`/`execSync`/`fetch` → code findings → **BLOCK**.
   - registry no longer has `6.0.0` (depublished) → **HIGH** `Added dependency not
     published`.
3. Findings are merged before scoring, so `riskScore`, `state` and the
   **HMAC-SHA256 attestation** all cover them.

## Verification harness

- Fixture tarball replicated from the published artifact (the real `keyv@6.0.0` is
  404 — a replica is used for tests).
- CLI regression: `src/cli/scan_node_modules.test.ts` (spawn, fixture with malicious
  `node_modules/keyv`): default → `findings: []` + coverage warning; with
  `--audit-node-modules` → exit 1 + `LIFECYCLE_CURL_BASH` CRITICAL.
- Oracle regression: `test/regression/intel/tarball-scan.test.ts` (network mocked):
  malicious added tarball → critical findings + `BLOCK` + signed attestation;
  depublished version → HIGH finding; env gate → no findings.
- CLI attestation: `src/cli/scan_attestation.test.ts` (tamper detection).
- Live red team (Cloud): `scripts/redteam_registry_intel.ts` — 7 probes across real
  packages, 0 false positives.

## Suite status

| Repo | Files | Tests |
|------|-------|-------|
| Cloud | 65 | 1281 |
| CLI | 55 | 1052 |
| Oracle | 15 | 289 |
