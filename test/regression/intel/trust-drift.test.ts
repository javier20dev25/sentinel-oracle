import { describe, it, expect } from 'vitest'
import { analyzeTrustDrift } from '../../../src/scanner/intel/trust-drift'

describe('analyzeTrustDrift', () => {
  it('returns low risk for no changes', () => {
    const result = analyzeTrustDrift([])
    expect(result.risk).toBe('low')
    expect(result.summary).toBe('No trust drift detected')
  })

  it('detects new workflow secrets', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: echo deploying
secrets:
  AWS_ACCESS_KEY_ID:
    required: true
  AWS_SECRET_ACCESS_KEY:
    required: true
  PRODUCTION_DB_URL:
    required: true`,
      },
    ])
    expect(result.newWorkflowSecrets.length).toBeGreaterThanOrEqual(2)
    expect(result.risk).toBe('high')
  })

  it('detects self-hosted runners', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: deploy.sh`,
      },
    ])
    expect(result.newRunners).toContain('self-hosted')
    expect(result.risk).not.toBe('low')
  })

  it('does not flag standard ubuntu runners', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm test`,
      },
    ])
    expect(result.newRunners).toHaveLength(0)
  })

  it('detects new deployment environments', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    environment: staging
    steps:
      - run: deploy.sh`,
      },
    ])
    expect(result.newEnvironments.length).toBeGreaterThanOrEqual(1)
  })

  it('detects permission escalations in workflows', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
permissions:
  contents: write
  id-token: write
  issues: admin`,
      },
    ])
    expect(result.permissionEscalations.length).toBeGreaterThanOrEqual(1)
    expect(['medium', 'high', 'critical']).toContain(result.risk)
  })

  it('detects new GitHub Apps beyond built-in set', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
jobs:
  deploy:
    steps:
      - uses: evil-app/malicious-action@v1
      - uses: another-evil-app/hook@main`,
      },
    ])
    expect(result.newGitHubApps).toContain('evil-app')
    expect(result.newGitHubApps).toContain('another-evil-app')
  })

  it('does not flag built-in apps', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/ci.yml',
        patch: `+
jobs:
  deps:
    steps:
      - uses: dependabot/fetch-metadata@v1`,
      },
    ])
    expect(result.newGitHubApps).toHaveLength(0)
  })

  it('detects new collaborators via CODEOWNERS', () => {
    const result = analyzeTrustDrift([
      {
        filename: 'CODEOWNERS',
        patch: '+\n+* @evil-collaborator\n+src/ @trusted-user\n+config/ @new-admin',
      },
    ], {
      knownCollaborators: ['trusted-user'],
    })
    expect(result.newCollaborators).toContain('evil-collaborator')
    expect(result.newCollaborators).toContain('new-admin')
    expect(result.newCollaborators).not.toContain('trusted-user')
  })

  it('detects branch protection removal', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/settings.yml',
        patch: `-
-required_status_checks:
-  contexts:
-    - "CI"
-required_pull_request_reviews:
-  dismiss_stale_reviews: true
-  require_code_owner_reviews: true
++allow_force_pushes: true`,
      },
    ])
    expect(result.removedBranchProtections.length).toBeGreaterThanOrEqual(1)
  })

  it('combines multiple signals into critical risk', () => {
    const result = analyzeTrustDrift([
      {
        filename: '.github/workflows/deploy.yml',
        patch: `+
permissions:
  contents: write
  id-token: write
jobs:
  deploy:
    runs-on: self-hosted
    environment: production
    steps:
      - uses: unknown-app/malicious@v1
secrets:
  AWS_SECRET_KEY:
    required: true
  DB_PASSWORD:
    required: true`,
      },
      {
        filename: 'CODEOWNERS',
        patch: '+@evil-user @another-evil',
      },
    ], {
      knownCollaborators: [],
      knownRunners: ['ubuntu-latest'],
      knownEnvironments: ['staging'],
    })
    expect(result.newGitHubApps.length).toBeGreaterThanOrEqual(1)
    expect(result.newWorkflowSecrets.length).toBeGreaterThanOrEqual(1)
    expect(result.permissionEscalations.length).toBeGreaterThanOrEqual(1)
    expect(result.risk).toBe('critical')
    console.log(`[Trust Drift] Combined risk: ${result.risk}, findings: ${result.summary}`)
  })
})
