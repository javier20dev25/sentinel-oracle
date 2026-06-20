# Security DNA

## What it is

Security DNA is an **aggregation layer** that synthesizes signals from existing Sentinel intel modules into a normalized capability vector for a repository. It describes what a repository *can do* at a point in time, not how risky it is.

The output is a `CapabilitySnapshot` — a set of counts across 14 observable capability dimensions:

| Field | Source module | What it measures |
|-------|--------------|------------------|
| `filesystem` | CapabilityIntel | Filesystem read/write operations |
| `network` | CapabilityIntel | Network requests / socket usage |
| `shell` | CapabilityIntel | Shell command execution |
| `dynamicCode` | CapabilityIntel | `eval()`, `exec()`, dynamic imports |
| `database` | CapabilityIntel | Database queries and connections |
| `crypto` | CapabilityIntel | Encryption, hashing, key material |
| `secrets` | TrustDriftIntel | New workflow secrets detected |
| `runners` | TrustDriftIntel | New self-hosted runners |
| `environments` | TrustDriftIntel | New deployment environments |
| `collaborators` | TrustDriftIntel | New collaborators added |
| `permissionEscalations` | TrustDriftIntel | Permission escalations in CI |
| `newDomains` | EndpointIntel | New external domains/endpoints |
| `newIntegrations` | ServiceIntel | New service integrations (SDKs) |
| `workflowCount` | WorkflowIntel | Number of CI workflow baselines |

## What it is NOT

- **Not a risk score.** `totalRiskScore` is included in the snapshot as a convenience for the scanner, but the DNA's primary role is descriptive, not evaluative. Risk assessment belongs to the Sentinel Risk Engine.
- **Not a detection module.** DNA does not scan or analyze files. It reads the output of other modules.
- **Not a prediction system.** No ML, no embeddings, no isolation forest. DNA only describes current and historical state.
- **Not a replacement for any existing module.** DNA aggregates; it does not duplicate.

## Data flow

```
PR Files
  ↓
Intel Modules (capabilities, endpoints, services, trust-drift, workflow, etc.)
  ↓
IntelReport
  ↓
buildCapabilitySnapshot(report)  ←  security-dna.ts
  ↓
CapabilitySnapshot               ←  14 raw integers
  ↓
Database (capability_snapshots table)
  ↓
GET /api/dna
  ↓
buildDNAReport(current, history) ←  computes drift/changes
  ↓
Security DNA UI (frontend)
```

## How `buildCapabilitySnapshot` works

1. Receives a complete `IntelReport` (output of `runIntelAnalysis`)
2. Reads specific fields from each intel module:
   - `report.capabilities` → filesystem, network, shell, dynamicCode, database, crypto (array lengths)
   - `report.endpoints` → newDomains (array length of `added`)
   - `report.services` → newIntegrations (array length of `added`)
   - `report.trustDrift` → secrets, runners, environments, collaborators, permissionEscalations
   - `report.workflowIntel` → workflowCount (baseline count)
3. Computes `totalRiskScore` by converting each module's risk label to points (critical=4, high=3, medium=2, low=1) and summing
4. Returns a flat `CapabilitySnapshot` object

## Database schema

```sql
CREATE TABLE IF NOT EXISTS capability_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,       -- raw JSON of CapabilitySnapshot
    created_at INTEGER NOT NULL
);
```

Snapshots are stored as raw JSON, never normalized. Normalization (percentages, trends) is computed by the UI at render time, so historical snapshots remain valid even if the normalization formula changes.

## How `buildDNAReport` works

1. Takes the latest `CapabilitySnapshot` as `current` and an array of previous snapshots as `history`
2. For each of the 14 capability fields, compares `current` vs the last known snapshot
3. Computes absolute change and percentage change per field
4. Generates a summary statement (e.g. "13 capability areas active, 5 changed since last snapshot")

## API

```
GET /api/dna
```

Requires authentication. Returns:

```json
{
  "current": { CapabilitySnapshot },
  "history": [ CapabilitySnapshot, ... ],
  "changes": [
    { "label": "Network", "current": 12, "previous": 10, "change": 2, "changePct": 20 },
    ...
  ],
  "summary": "13 capability areas active, 5 changed since last snapshot",
  "snapshotCount": 42
}
```

If no repository is configured or no snapshots exist, returns `current: null` with an explanatory summary.

## Frontend

Located at `public/app.js:loadDNA()` and `public/index.html:#dna-section`.

- Capability bars rendered as a 2-column grid
- Each bar shows the capability name, current count, and a colored fill proportional to the max value
- Drift indicators (▲/▼) next to fields that changed since last scan
- A "Drift since last scan" section listing all fields with non-zero change
- Snapshot count displayed at the bottom

## Limitations (current)

- **Summary is flat.** The summary statement counts changes but does not identify *drivers* (e.g., "network increased due to AWS SDK"). Template-based driver extraction is a future improvement.
- **`totalRiskScore` mixes concerns.** It exists in the snapshot for convenience but conceptually mixes capability state with risk assessment. It should be treated as a secondary signal.
- **No historical comparisons beyond sequential.** The `changes` array only compares to the immediately preceding snapshot. Multi-point trend analysis (7d/30d/all) is not yet implemented in the DNA layer (though it exists in WorkflowIntel's multi-window baselines).
- **No cross-repository comparison.** DNA currently describes one repo in isolation. Comparing DNA profiles across repos is future work.
- **Snapshot frequency depends on scan frequency.** Snapshots are created only when a PR is scanned. Repos with few PRs will have sparse history.

## Future directions

- **Evolution Timeline** — visualize capability drift over time (this endpoint already returns `history[]`)
- **Attack Surface Evolution** — track which specific endpoints/services/domains appeared across snapshots
- **Drivers extraction** — template-based summary that identifies which changes drove capability shifts
- **Cross-repo comparison** — compare DNA profiles of different repositories
