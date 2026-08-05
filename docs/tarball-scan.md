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

## Source layout

- `src/scanner/intel/deep-dependency.ts` — tar/gzip parsing, registry resolution,
  `analyzeDependencyTarball` (added deps), `analyzeDependencyDelta` (updated deps),
  `tarballToPRFiles`, `lifecycleToFindings`, `deltaToFindings`.
- `src/scanner/intel/index.ts` — `runIntelAnalysis` wiring + env gate.
- `src/scanner/index.ts` — merges `dependencyTarballFindings` into the signed result.

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
