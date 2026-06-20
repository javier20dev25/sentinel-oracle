import type { PRFile } from '../rules'
import type { PermissionIntel, IntelRisk } from './types'

const PERMISSION_KEYWORDS = [
  'contents', 'issues', 'pull-requests', 'packages', 'security-events',
  'actions', 'deployments', 'statuses', 'checks', 'repository-projects',
  'discussions', 'pages', 'id-token', 'attestations',
]

const READ = 'read'
const WRITE = 'write'
const NONE = 'none'

function parsePermissionsBlock(yaml: string): Record<string, string> {
  const perms: Record<string, string> = {}
  const block = yaml.match(/permissions:\s*\n([\s\S]*?)(?=\n\S|\n*$)/)
  if (!block) return perms

  const lines = block[1].split('\n')
  for (const line of lines) {
    const match = line.match(/^\s{2,}([a-zA-Z_-]+):\s*(\w+)/)
    if (match) {
      perms[match[1]] = match[2]
    }
  }
  return perms
}

export function analyzePermissions(files: PRFile[]): PermissionIntel | undefined {
  const workflowFiles = files.filter(f => /\.ya?ml$/.test(f.filename) && /workflow|\.github/i.test(f.filename))

  for (const file of workflowFiles) {
    const patch = file.patch || ''
    const lines = patch.split('\n')

    // Reconstruct full old/new file content from patch
    const oldLines: string[] = []
    const newLines: string[] = []
    let inOld = false
    let inNew = false

    // We'll use a simpler approach: look at the patch itself for permissions: blocks
    const removedBlocks: string[] = []
    const addedBlocks: string[] = []

    let currentBlock: string[] = []
    let currentIsAdd = false
    let currentIsRemove = false

    for (const line of lines) {
      if (line.startsWith('@@')) {
        if (currentBlock.length > 0) {
          if (currentIsAdd) addedBlocks.push(currentBlock.join('\n'))
          if (currentIsRemove) removedBlocks.push(currentBlock.join('\n'))
        }
        currentBlock = []
        currentIsAdd = false
        currentIsRemove = false
        continue
      }
      if (line.startsWith('+') && !line.startsWith('++')) {
        if (!currentIsAdd && currentIsRemove && currentBlock.length > 0) {
          removedBlocks.push(currentBlock.join('\n'))
          currentBlock = []
        }
        currentIsAdd = true
        currentIsRemove = false
        currentBlock.push(line.slice(1))
      } else if (line.startsWith('-') && !line.startsWith('--')) {
        if (!currentIsRemove && currentIsAdd && currentBlock.length > 0) {
          addedBlocks.push(currentBlock.join('\n'))
          currentBlock = []
        }
        currentIsAdd = false
        currentIsRemove = true
        currentBlock.push(line.slice(1))
      } else if (line.startsWith(' ') && currentBlock.length > 0) {
        currentBlock.push(line.slice(1))
      } else {
        if (currentBlock.length > 0) {
          if (currentIsAdd) addedBlocks.push(currentBlock.join('\n'))
          if (currentIsRemove) removedBlocks.push(currentBlock.join('\n'))
        }
        currentBlock = []
        currentIsAdd = false
        currentIsRemove = false
      }
    }
    if (currentBlock.length > 0) {
      if (currentIsAdd) addedBlocks.push(currentBlock.join('\n'))
      if (currentIsRemove) removedBlocks.push(currentBlock.join('\n'))
    }

    // Check if any block contains permissions
    const hasPermissions = (block: string) => /\bpermissions\s*:/.test(block)
    const permChanges = addedBlocks.filter(hasPermissions)

    if (permChanges.length > 0) {
      const addedPermissions: string[] = []
      const removedPermissions: string[] = []
      const after = parsePermissionsBlock(permChanges.join('\n'))
      const before = parsePermissionsBlock(removedBlocks.filter(hasPermissions).join('\n'))

      for (const [key, val] of Object.entries(after)) {
        if (val === WRITE) {
          addedPermissions.push(key)
        }
      }

      return {
        summary: `Permissions changed in ${file.filename}`,
        file: file.filename,
        before,
        after,
        addedPermissions,
        removedPermissions,
        risk: addedPermissions.length > 0 ? 'high' : 'medium',
      }
    }
  }

  return undefined
}
