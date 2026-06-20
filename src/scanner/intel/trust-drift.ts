import type { TrustDriftIntel, IntelRisk } from './types'

interface TrustDriftOptions {
  knownCollaborators?: string[]
  knownGitHubApps?: string[]
  knownEnvironments?: string[]
  knownRunners?: string[]
  knownSecrets?: string[]
  knownBranchProtections?: string[]
  previousWorkflowPermissions?: Record<string, string[]>
}

const BUILTIN_APPS = ['dependabot', 'renovate', 'codecov', 'sonarcloud', 'snyk', 'lgtm', 'codeql']

function extractSecretsFromWorkflow(patch: string): string[] {
  const secrets: string[] = []
  const lines = patch.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.match(/^\s*secrets:/i)) {
      let j = i + 1
      while (j < lines.length && lines[j].match(/^\s{2,}/)) {
        const match = lines[j].match(/^\s{2,}([A-Z_]+):/)
        if (match) secrets.push(match[1])
        j++
      }
    }
    const secretRefs = line.match(/\${{ secrets\.([A-Z_]+) }}/g)
    if (secretRefs) {
      for (const ref of secretRefs) {
        const m = ref.match(/secrets\.([A-Z_]+)/)
        if (m) secrets.push(m[1])
      }
    }
  }
  return [...new Set(secrets)]
}

function extractRunnersFromWorkflow(patch: string): string[] {
  const runners: string[] = []
  const lines = patch.split('\n')
  for (const line of lines) {
    const match = line.match(/runs-on:\s*(.+)/)
    if (match) {
      runners.push(match[1].trim())
    }
  }
  return [...new Set(runners)]
}

function extractEnvironmentsFromWorkflow(patch: string): string[] {
  const environments: string[] = []
  const lines = patch.split('\n')
  for (const line of lines) {
    const match = line.match(/environment:\s*(.+)/)
    if (match) {
      environments.push(match[1].trim())
    }
  }
  return [...new Set(environments)]
}

function extractPermissionsFromWorkflow(patch: string): { permissions: string[]; escalation: boolean } {
  const permissions: string[] = []
  let inPermissions = false
  const lines = patch.split('\n')

  for (const line of lines) {
    if (line.match(/^\s*permissions:/)) {
      inPermissions = true
      continue
    }
    if (inPermissions) {
      if (line.match(/^\s+\w+:/)) {
        const match = line.match(/^\s+(\w+):/)
        if (match) {
          const perm = match[1]
          const value = line.split(':')[1]?.trim()
          permissions.push(`${perm}=${value}`)
          // Escalation: write or admin permissions
          if (value === 'write' || value === 'admin') {
            permissions.push(`ESCALATION:${perm}`)
          }
        }
      } else {
        inPermissions = false
      }
    }
  }
  return {
    permissions,
    escalation: permissions.some(p => p.startsWith('ESCALATION:')),
  }
}

function extractCollaboratorsFromPatch(patch: string): string[] {
  const collaborators: string[] = []
  const lines = patch.split('\n')
  for (const line of lines) {
    const codeownerMatch = line.match(/@([\w-]+(\/[\w-]+)?)/g)
    if (codeownerMatch) {
      for (const m of codeownerMatch) {
        collaborators.push(m.startsWith('@') ? m.slice(1) : m)
      }
    }
    if (line.includes('admin:') || line.includes('maintainer:') || line.includes('owner:')) {
      const match = line.match(/:\s*['"]?([\w-]+)['"]?/)
      if (match) collaborators.push(match[1])
    }
  }
  return [...new Set(collaborators)]
}

function extractBranchProtectionChanges(patch: string): { removed: string[]; modified: string[] } {
  const removed: string[] = []
  const modified: string[] = []
  const lines = patch.split('\n')
  for (const line of lines) {
    if (line.match(/^-\s+required_status_checks/) || line.match(/^-\s+required_pull_request_reviews/)) {
      removed.push(line.replace(/^-\s+/, '').trim())
    }
    if (line.match(/^\+\s+required_status_checks/) || line.match(/^\+\s+required_pull_request_reviews/)) {
      modified.push(line.replace(/^\+\s+/, '').trim())
    }
    if (line.includes('required_status_checks:') && line.startsWith('-')) {
      removed.push('required_status_checks')
    }
    if (line.includes('dismiss_stale_reviews:') && line.includes('false')) {
      removed.push('dismiss_stale_reviews=false')
    }
    if (line.includes('require_code_owner_reviews:') && line.includes('false')) {
      removed.push('require_code_owner_reviews=false')
    }
  }
  return { removed, modified }
}

function extractGitHubAppsFromWorkflow(patch: string): string[] {
  const apps: string[] = []
  const lines = patch.split('\n')
  for (const line of lines) {
    // Match: uses: some-app/some-action@v1
    const match = line.match(/uses:\s+([\w-]+)\/[\w-]+@/)
    if (match) {
      const app = match[1].toLowerCase()
      if (!BUILTIN_APPS.includes(app)) {
        apps.push(match[1])
      }
    }
    // Match: app_id, app slug, or github_app
    if (line.includes('github_app:') || line.includes('app_id:')) {
      const m = line.match(/:\s*['"]?([\w-]+)['"]?/)
      if (m) apps.push(m[1])
    }
  }
  return [...new Set(apps)]
}

export function analyzeTrustDrift(
  prFiles: { filename: string; patch?: string }[],
  options?: TrustDriftOptions,
): TrustDriftIntel {
  const newCollaborators: string[] = []
  const newGitHubApps: string[] = []
  const newWorkflowSecrets: string[] = []
  const newEnvironments: string[] = []
  const newRunners: string[] = []
  const removedBranchProtections: string[] = []
  const permissionEscalations: string[] = []

  for (const file of prFiles) {
    if (!file.patch) continue

    // Detect collaborators from CODEOWNERS and config files
    if (file.filename.includes('CODEOWNERS') || file.filename.includes('.github/')) {
      const collabs = extractCollaboratorsFromPatch(file.patch)
      for (const c of collabs) {
        if (!options?.knownCollaborators?.includes(c)) {
          newCollaborators.push(c)
        }
      }
    }

    // Detect workflow changes
    if (file.filename.startsWith('.github/workflows/') || file.filename.startsWith('.github/actions/')) {
      // Secrets
      const secrets = extractSecretsFromWorkflow(file.patch)
      for (const s of secrets) {
        if (!options?.knownSecrets?.includes(s)) {
          newWorkflowSecrets.push(s)
        }
      }

      // Runners
      const runners = extractRunnersFromWorkflow(file.patch)
      for (const r of runners) {
        if (!options?.knownRunners?.includes(r) && !r.includes('ubuntu') && !r.includes('windows') && !r.includes('macos')) {
          newRunners.push(r)
        }
      }

      // Environments
      const envs = extractEnvironmentsFromWorkflow(file.patch)
      for (const e of envs) {
        if (!options?.knownEnvironments?.includes(e)) {
          newEnvironments.push(e)
        }
      }

      // GitHub Apps
      const apps = extractGitHubAppsFromWorkflow(file.patch)
      for (const a of apps) {
        if (!options?.knownGitHubApps?.includes(a)) {
          newGitHubApps.push(a)
        }
      }

      // Permission escalations
      const { escalation, permissions } = extractPermissionsFromWorkflow(file.patch)
      if (escalation) {
        const newPerms = permissions.filter(p => p.startsWith('ESCALATION:'))
        for (const p of newPerms) {
          permissionEscalations.push(p.replace('ESCALATION:', ''))
        }
      }
    }

    // Detect branch protection changes
    if (file.filename.includes('branch-protection') || file.filename.includes('.github/settings.yml')) {
      const { removed } = extractBranchProtectionChanges(file.patch)
      removedBranchProtections.push(...removed)
    }
  }

  // Compute risk
  const score = newCollaborators.length * 2 + newGitHubApps.length * 3 + newWorkflowSecrets.length * 3
    + newEnvironments.length * 2 + newRunners.length * 3 + removedBranchProtections.length * 4
    + permissionEscalations.length * 4

  let risk: IntelRisk = 'low'
  if (score >= 10) risk = 'critical'
  else if (score >= 6) risk = 'high'
  else if (score >= 3) risk = 'medium'

  const findings: string[] = []
  if (newCollaborators.length) findings.push(`${newCollaborators.length} new collaborator(s)`)
  if (newGitHubApps.length) findings.push(`${newGitHubApps.length} new GitHub App(s)`)
  if (newWorkflowSecrets.length) findings.push(`${newWorkflowSecrets.length} new secret(s)`)
  if (newEnvironments.length) findings.push(`${newEnvironments.length} new environment(s)`)
  if (newRunners.length) findings.push(`${newRunners.length} new runner(s)`)
  if (removedBranchProtections.length) findings.push(`${removedBranchProtections.length} branch protection(s) removed`)
  if (permissionEscalations.length) findings.push(`${permissionEscalations.length} permission escalation(s)`)

  return {
    summary: findings.length > 0 ? `Trust drift: ${findings.join(', ')}` : 'No trust drift detected',
    newCollaborators,
    newGitHubApps,
    newWorkflowSecrets,
    newEnvironments,
    newRunners,
    removedBranchProtections,
    permissionEscalations,
    risk,
  }
}
