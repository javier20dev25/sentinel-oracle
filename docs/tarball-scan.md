# Tarball Scan (Added & Updated Dependencies)

The Oracle historically reasoned about dependencies from **manifest lines alone**
(a `package.json` diff shows only `"keyv": "^6.0.0"` — never the contents of the
published tarball). The **ChainDrop / Shai-Hulud** incident (Aug 4 2026) exploited
exactly that gap: a compromised maintainer account published a malicious tarball
whose `preinstall` script ran a dropper (`node setup.mjs`), then depublished it.

This document describes the tarball-scan capability added to close the gap.

---

## What it does

`runIntelAnalysis` now downloads and inspects the **actual published tarball** of
dependencies a PR adds or updates:

- **Added deps** (the ChainDrop vector): the requested version is resolved against
  the npm registry and the single tarball is scanned. Because there is no previous
  version to diff against, every signal is treated as new.
- **Updated deps**: the existing two-tarball diff runs as before (file listing,
  domains, capabilities, scripts, binaries).
- **Unpublished versions**: if the requested version does **not** exist in the
  registry, a `high` finding `Added dependency version not published` is emitted —
  publishing then depublishing a version is the known worm signature.

Signals surfaced as typed `Finding`s (same shape as `runRules`, so they flow into
the risk score, the `PASS | REVIEW | BLOCK` verdict, and the HMAC-SHA256
attestation):

| Signal | Finding | Severity |
|--------|---------|----------|
| `preinstall`/`install`/`postinstall` script that downloads or shells out | `Dangerous lifecycle script in added dependency` | critical |
| Any install-time lifecycle script | `Install-time script in added dependency` | medium |
| Shell-execution capability in tarball code | `Shell execution capability in dependency tarball` | critical |
| Prebuilt binaries shipped | `Prebuilt binaries in dependency tarball` | high |
| Network endpoints referenced | `Network endpoints in dependency tarball` | medium |
| Requested version not in registry | `Added dependency version not published` | high |

In addition, every text file in the tarball is fed through the existing `runRules`
engine (as synthetic files under `node_modules/<name>/`), so `eval()`, OS command
execution, network exfiltration, secrets, etc. inside a payload are detected with
the standard rule set.

The tarball-derived findings are merged into the scan result **before** scoring and
attestation, so they change `riskScore`, `state`, the severity counts and the signed
attestation — a tampered report can be detected exactly as before.

## Gating

Network tarball scanning is on by default and can be disabled with:

```
SENTINEL_TARBALL_SCAN=0
```

Hermetic test suites set this variable; it is also available as an option on
`runIntelAnalysis(files, { tarballScan: boolean })`.

### Budget (not a fixed cap)

The tarball phase analyzes dependencies **until it consumes the configured
resource budget** — it is not a fixed "scan N packages" cap. If the budget runs
out, scanning stops **explicitly** and the result reports that the scan was
truncated, so callers never mistake a truncated scan for full coverage.

Registry work is bounded by a `TarballBudget` (`src/scanner/intel/tarball-budget.ts`).
The governing dimensions are **real resources — bytes and wall-clock time**:

| Env | Dimension | Default |
|-----|-----------|---------|
| `SENTINEL_TARBALL_BUDGET_BYTES` | max total tarball bytes | 50 MB |
| `SENTINEL_TARBALL_BUDGET_TIME` | max wall-clock ms | 60 s |
| `SENTINEL_TARBALL_BUDGET_CONCURRENCY` | max parallel fetches | 2 |
| `SENTINEL_TARBALL_BUDGET_PACKAGES` | **safety ceiling** for work items | 200 |

The package count is deliberately **not** a truncation dimension: it only
guards the queue against a pathological manifest (e.g. 10k entries) and defaults
high enough to never bind on a realistic PR. Truncation is driven by
bytes/time, so "120 packages of 3 KB" all get scanned while "3 packages of
200 MB" stop early.

**Bytes are hard.** `download()` reserves the expected size (from the response's
`Content-Length`) **before** reading the body. If the reservation would exceed
the remaining budget, the body is never consumed — spent+reserved can never
overshoot `maxBytes`, even with concurrent workers. Time is soft under
concurrency: in-flight downloads finish, no new ones start.

A hard byte stop is never misreported as a finding: when a tarball is skipped
because the budget is exhausted, the scan result records `skipped: 'budget'`
instead of the `Added dependency version not published` finding (that finding
is reserved for versions the registry genuinely lacks).

Added and updated deps each run with their own budget (a resource-scoped batch);
their telemetry is merged into one report.

### Scan telemetry

Every tarball phase exposes a `tarballScanTelemetry` block on the intel report
(same shape that feeds dashboards):

```json
{
  "scanId": "…",
  "packagesRequested": 38,
  "packagesScanned": 24,
  "cacheHits": 0,
  "cacheMisses": 24,
  "downloadMs": 4123,
  "analysisMs": 832,
  "bytesDownloaded": 18432902,
  "reasonTruncated": "BYTE_BUDGET"
}
```

`reasonTruncated` is `null` when everything requested was analyzed, otherwise
`BYTE_BUDGET` | `TIME_BUDGET` | `SAFETY_CEILING`. `cacheHits`/`cacheMisses` are
the observability hooks of the content-intelligence cache (below): on a hit the
bytes and time are zero and no download happens; `cacheMisses` counts every item
the cache could not answer.

## Content-intelligence cache (identity-based)

Re-scanning the same tarball on every PR wastes registry bandwidth and adds
latency to the gate. The cache keys on **what the artifact actually is** — the
sha512 of its bytes — never on `name@version`:

- **Content identity** is derived from npm's own `dist.integrity` SRI
  (`sha512-<base64>` in registry metadata, normalized to the canonical
  `sha512:<hex>` content id). No SRI → no identity → the cache is a silent
  no-op and the tarball is scanned as before.
- **Verdict record** (`ContentIntelRecord`) holds the state
  (`KNOWN_SAFE | SUSPICIOUS | MALICIOUS | REVOKED`), seen-in-repos history, the
  evidence, the **`scannerVersion`** that produced it, and an HMAC-SHA256
  signature. A tampered or stale row fails signature verification on read and is
  treated as a miss — a corrupted cache can never flip a verdict.
- **Cache hit** (a verified, decisive, non-stale verdict for the same content id
  under the current scanner version) replays the recorded findings verbatim and
  skips the download entirely. A hit `touch`es the record so the seen-in-repos
  counter stays accurate.
- **Integrity gate before caching**: a fresh scan only records its verdict when
  the downloaded bytes actually match the registry SRI. A mismatch raises a
  `medium` `Dependency tarball integrity mismatch` finding and **never** caches —
  that is the signal of a registry integrity failure or a tampered download.
- **Revalidation**: a `scannerVersion` bump (scanner/rules upgrade), age past the
  TTL (7 days), a pending state, or an unverified row all force a re-scan. A
  `REVOKED` record (depublished package, future intelligence feed) never counts
  as a hit until re-verified.

The store is a seam: the Oracle ships a persistent SQLite implementation
(`content-intel.db`, HMAC key in `.content_intel_key`) created lazily in
`~/.sentinel-oracle`, and the multi-tenant Cloud store implements the same
`ContentIntelStore` interface. Disable with `SENTINEL_CONTENT_INTEL=0`; override
the database directory with `SENTINEL_CONTENT_INTEL_DB_DIR`.

## Source layout

- `src/scanner/intel/deep-dependency.ts` — tar/gzip parsing, registry resolution,
  `analyzeDependencyTarball` (added deps), `analyzeDependencyDelta` (updated deps),
  `tarballToPRFiles`, `lifecycleToFindings`, `deltaToFindings`. Also owns the
  cache lookup **before** the download and the SRI verification after it.
- `src/scanner/intel/index.ts` — `runIntelAnalysis` wiring + env gate + cache
  record/replay of findings.
- `src/scanner/index.ts` — merges `dependencyTarballFindings` into the signed result.
- `src/scanner/intel/content-intel/` — the cache: `identity.ts` (SRI/sha512),
  `state.ts` (state machine), `record.ts` (signed `ContentIntelRecord`),
  `store.ts` (interface + in-memory + SQLite), `scanner-version.ts` (payload
  version gate).

## Why not a dedicated standalone scanner?

Building a separate "tarball scanner" product was evaluated and rejected as
**not ROI-positive**:

- The download, extraction and heuristic capability analysis are a **thin layer**
  over the registry — roughly 150 lines of shared logic, not a product.
- A dedicated scanner would need its own CLI, storage, auth, signing and CI wiring,
  multiplying surface area and maintenance for near-zero detection gain.
- The detection value only materializes when tarball findings are **fused into the
  PR gate** (verdict + attestation). A standalone tool that only prints findings is
  advisory, not enforcement.
- The existing three products already own the pieces: the Oracle owns the PR gate,
  the CLI owns local verification (`verify-pkg`), and the Cloud owns registry
  manifest intelligence. Embedding tarball scanning in the Oracle (and CLI) reuses
  that infrastructure.

Hence: tarball scanning was embedded in the Oracle and CLI rather than shipped as a
fourth product.

## Tests

`test/regression/intel/tarball-scan.test.ts` (network mocked):

- malicious added tarball → critical findings + `BLOCK` + signed attestation
- range version resolution through registry metadata
- depublished-version detection
- scan disabled via env → no tarball findings
- updated-dep two-tarball diff still works
- budget e2e: safety ceiling stops the queue without truncating a started scan
- budget e2e: byte budget too small → headers fetched, **body never read**,
  `reasonTruncated: BYTE_BUDGET`, zero findings (never misreported as unpublished)
- budget e2e: exactly one tarball fits, the next is refused and nothing overshoots
- budget e2e: no fixed cap — 3 packages all scan under a larger budget,
  `reasonTruncated: null`
- unit: `reserve`/`settle` accounting, refusal overflow, concurrent map can never
  overshoot `maxBytes`, time-out truncation, and telemetry shape

`test/regression/intel/content-intel.test.ts` (network mocked, in-memory store):

- identity: canonical content id from bytes, SRI `sha512-<base64>` normalization,
  malformed-integrity rejection, byte-verification against the SRI
- state machine: `UNKNOWN → SCANNING → verdict → REVOKED`, revalidation
  transitions, invalid-transition errors, risk ⇄ verdict mapping
- signed records: sign/verify roundtrip, tamper detection (including the
  signature field itself), seen-in-repos touching, revalidation on version/age,
  cache-hit preconditions, revoke
- store: verdict transition on re-record, tampered rows never read back
- e2e: first scan misses + records a verdict; second scan **hits** with identical
  findings, `cacheHits: 1`, `bytesDownloaded: 0`, zero network reads
- e2e: different repo increments the seen-in-repos counter
- e2e: integrity mismatch raises the finding and is **never** cached (still
  re-downloaded)
- e2e: registry without `dist.integrity` → cache is a no-op (identity unavailable)
