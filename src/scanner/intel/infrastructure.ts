import type { PRFile } from '../rules'
import type { InfrastructureIntel, IntelRisk } from './types'

const DETECTORS: { aspect: string; filePattern: RegExp; checks: { label: string; pattern: RegExp; risk: IntelRisk; impact: (m: RegExpExecArray) => string }[] }[] = [
  {
    aspect: 'Dockerfile',
    filePattern: /(Dockerfile|\.dockerignore)/,
    checks: [
      { label: 'Root user', pattern: /^USER\s+root$/m, risk: 'high', impact: () => 'Container runs as root' },
      { label: 'Exposed port', pattern: /^EXPOSE\s+(\d+)/m, risk: 'low', impact: (m) => `Port ${m[1]} exposed` },
      { label: 'Latest tag', pattern: /FROM\s+\S+:\s*latest\s*$/m, risk: 'medium', impact: () => 'Uses :latest tag — non-reproducible' },
      { label: 'Add vs Copy', pattern: /^ADD\s/m, risk: 'medium', impact: () => 'ADD used instead of COPY — potential build cache issue' },
      { label: 'Sensitive env', pattern: /^ENV\s+(?:\w*[Pp]ASS\w*|\w*[Ss][Ee][Cc][Rr][Ee][Tt]\w*|\w*[Tt][Oo][Kk][Ee][Nn]\w*|=)/m, risk: 'critical', impact: () => 'Sensitive data in ENV layers' },
      { label: 'Privileged', pattern: /--privileged/m, risk: 'critical', impact: () => 'Privileged mode enabled' },
      { label: 'Slim variant', pattern: /FROM\s+\S+:(alpine|slim|slim-\w+)/m, risk: 'low', impact: () => 'Uses slim/alpine variant' },
    ],
  },
  {
    aspect: 'Docker Compose',
    filePattern: /(docker-compose\.ya?ml|compose\.ya?ml)/,
    checks: [
      { label: 'Port mapping', pattern: /ports:\s*\n\s+-\s*"(\d+:\d+)"/m, risk: 'low', impact: (m) => `Port mapping: ${m[1]}` },
      { label: 'Root user', pattern: /user:\s*['"]?root['"]?/m, risk: 'high', impact: () => 'Service runs as root' },
      { label: 'Environment secrets', pattern: /environment:\s*\n(\s+-\s*\w*[Ss][Ee][Cc][Rr][Ee][Tt]\w*\s*=\s*)/m, risk: 'high', impact: () => 'Secrets in environment variables' },
      { label: 'Privileged mode', pattern: /privileged:\s*true/m, risk: 'critical', impact: () => 'Privileged mode enabled' },
      { label: 'Volume mounts', pattern: /volumes:\s*\n(\s+-\s*\S+)/m, risk: 'low', impact: () => 'Volume mounts detected' },
      { label: 'Network mode host', pattern: /network_mode:\s*host/m, risk: 'medium', impact: () => 'Host network mode — reduced isolation' },
    ],
  },
  {
    aspect: 'Kubernetes',
    filePattern: /\.ya?ml$/,
    checks: [
      { label: 'Privileged container', pattern: /privileged:\s*true/m, risk: 'critical', impact: () => 'Privileged container' },
      { label: 'Host network', pattern: /hostNetwork:\s*true/m, risk: 'medium', impact: () => 'Host network access' },
      { label: 'Run as root', pattern: /runAsUser:\s*0/m, risk: 'high', impact: () => 'Container runs as root (UID 0)' },
      { label: 'Secrets from env', pattern: /env:\s*\n(\s+-\s*name:\s*\w*[Ss][Ee][Cc][Rr][Ee][Tt]\w*\s*\n\s+valueFrom:\s*\n\s+secretKeyRef)/m, risk: 'low', impact: () => 'References Kubernetes secrets' },
      { label: 'Allow privilege escalation', pattern: /allowPrivilegeEscalation:\s*true/m, risk: 'critical', impact: () => 'Privilege escalation allowed' },
      { label: 'Read-only root FS', pattern: /readOnlyRootFilesystem:\s*(true|false)/m, risk: 'low', impact: (m) => m[1] === 'true' ? 'Read-only root filesystem' : 'Writable root filesystem' },
    ],
  },
  {
    aspect: 'Terraform',
    filePattern: /\.tf$/,
    checks: [
      { label: 'Hardcoded secret', pattern: /(password|secret|token|api_key)\s*=\s*['"`][^'"`]+['"`]/im, risk: 'critical', impact: () => 'Hardcoded secret in Terraform' },
      { label: 'Public S3 bucket', pattern: /acl\s*=\s*['"`]public-(read|write)['"`]/im, risk: 'high', impact: (m) => `S3 bucket has public-${m[1]} ACL` },
      { label: 'Open security group', pattern: /cidr_blocks\s*=\s*\[['"`]0\.0\.0\.0\/0['"`]\]/m, risk: 'high', impact: () => 'Security group open to 0.0.0.0/0' },
      { label: 'Unencrypted storage', pattern: /encrypted\s*=\s*false/m, risk: 'high', impact: () => 'Unencrypted storage' },
    ],
  },
  {
    aspect: 'Nginx',
    filePattern: /nginx\.conf|\.nginx/,
    checks: [
      { label: 'Server tokens', pattern: /server_tokens\s+off/m, risk: 'low', impact: () => 'Server tokens hidden' },
      { label: 'SSL config', pattern: /ssl_certificate\s+/m, risk: 'low', impact: () => 'SSL configured' },
      { label: 'Exposed .git', pattern: /location\s+~\/\\.git/m, risk: 'critical', impact: () => '.git directory exposed' },
      { label: 'Proxy pass', pattern: /proxy_pass\s+/m, risk: 'low', impact: () => 'Proxy pass configured' },
    ],
  },
]

export function analyzeInfrastructure(files: PRFile[]): InfrastructureIntel | undefined {
  const changes: InfrastructureIntel['changes'] = []

  for (const file of files) {
    const content = file.patch || ''

    for (const detector of DETECTORS) {
      if (!detector.filePattern.test(file.filename)) continue

      for (const check of detector.checks) {
        check.pattern.lastIndex = 0
        let match
        while ((match = check.pattern.exec(content)) !== null) {
          const after = check.impact(match)
          changes.push({
            aspect: `${detector.aspect}: ${check.label}`,
            before: 'unknown',
            after,
            impact: after,
          })
        }
      }
    }
  }

  if (changes.length === 0) return undefined

  let risk: IntelRisk = 'low'
  if (changes.some(c => /critical|privileged|root|secret|public|\.git/i.test(c.impact))) risk = 'critical'
  else if (changes.some(c => /medium|open|writable/i.test(c.impact))) risk = 'medium'
  else if (changes.length > 1) risk = 'medium'

  return { summary: `${changes.length} infrastructure change${changes.length > 1 ? 's' : ''}`, changes, risk }
}
