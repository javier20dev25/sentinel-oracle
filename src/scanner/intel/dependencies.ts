import type { PRFile } from '../rules'
import type { DependencyIntel, IntelRisk } from './types'

export function analyzeDependencies(files: PRFile[]): DependencyIntel | undefined {
  const manifestFiles = files.filter(f =>
    /(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|pom\.xml|Gemfile|Gemfile\.lock)/.test(f.filename)
  )
  if (manifestFiles.length === 0) return undefined

  const added: DependencyIntel['added'] = []
  const updated: DependencyIntel['updated'] = []
  const removed: DependencyIntel['removed'] = []
  const riskSignals: DependencyIntel['riskSignals'] = []

  for (const file of manifestFiles) {
    const patch = file.patch || ''
    const lines = patch.split('\n')

    for (const line of lines) {
      if (!line.startsWith('+') && !line.startsWith('-')) continue
      const isAdd = line.startsWith('+')
      const content = line.slice(1).trim()

      if (file.filename.endsWith('package.json')) {
        const depMatch = content.match(/"([^"]+)":\s*"\^?~?([^"]+)"/)
        if (depMatch) {
          const [, name, version] = depMatch
          if (isAdd) {
            added.push({ name, version })
            if (version.startsWith('0') || version.includes('alpha') || version.includes('beta') || version.includes('rc')) {
              riskSignals.push({ package: name, signal: `Pre-release version: ${version}`, risk: 'medium' })
            }
          } else {
            removed.push({ name, version })
          }
        }
      }

      if (file.filename.endsWith('requirements.txt')) {
        const reqMatch = content.match(/^([a-zA-Z0-9_.-]+)([><=!~]+)(.+)/)
        if (reqMatch) {
          const [, name, , version] = reqMatch
          if (isAdd) added.push({ name, version })
          else removed.push({ name, version })
        } else if (isAdd && /^[a-zA-Z0-9_.-]+$/.test(content)) {
          added.push({ name: content, version: '*' })
        }
      }

      if (file.filename.endsWith('go.mod')) {
        const goMatch = content.match(/^\s*([a-zA-Z0-9_.\/-]+)\s+v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)/)
        if (goMatch) {
          const [, name, version] = goMatch
          if (isAdd) added.push({ name, version })
          else removed.push({ name, version })
        }
      }

      if (file.filename.endsWith('Cargo.toml')) {
        const cargoMatch = content.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/)
        if (cargoMatch) {
          const [, name, version] = cargoMatch
          if (isAdd) added.push({ name, version })
          else removed.push({ name, version })
        }
      }

      if (file.filename.endsWith('pom.xml') || file.filename.endsWith('.pom')) {
        const grp = content.match(/<groupId>([^<]+)<\/groupId>/)
        const art = content.match(/<artifactId>([^<]+)<\/artifactId>/)
        const ver = content.match(/<version>([^<]+)<\/version>/)
        if (isAdd && grp && art && ver) {
          added.push({ name: `${grp[1]}:${art[1]}`, version: ver[1] })
        }
      }
    }
  }

  // Detect major version bumps in updated deps
  for (const dep of added) {
    const existing = removed.find(r => r.name === dep.name)
    if (existing) {
      const fromMajor = parseInt(existing.version, 10)
      const toMajor = parseInt(dep.version, 10)
      const isMajor = !isNaN(fromMajor) && !isNaN(toMajor) && toMajor > fromMajor
      updated.push({ name: dep.name, fromVersion: existing.version, toVersion: dep.version, isMajor })
      if (isMajor) {
        riskSignals.push({ package: dep.name, signal: `Major version bump: ${existing.version} → ${dep.version}`, risk: 'high' })
      }
      // Remove from added/removed since it's an update
      added.splice(added.indexOf(dep), 1)
      removed.splice(removed.indexOf(existing), 1)
    }
  }

  if (added.length === 0 && updated.length === 0 && removed.length === 0) return undefined

  let risk: IntelRisk = 'low'
  const hasMajor = riskSignals.some(s => s.risk === 'high' || s.risk === 'critical')
  const hasNew = added.length > 0
  if (hasMajor) risk = 'high'
  else if (hasNew) risk = 'medium'

  const parts: string[] = []
  if (added.length > 0) parts.push(`${added.length} added`)
  if (updated.length > 0) parts.push(`${updated.length} updated`)
  if (removed.length > 0) parts.push(`${removed.length} removed`)

  return { summary: parts.join(', ') || 'No changes', added, updated, removed, newToRepo: [], riskSignals, risk }
}
