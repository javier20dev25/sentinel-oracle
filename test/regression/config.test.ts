import { vi, describe, it, expect, beforeAll, afterAll } from 'vitest'
import * as path from 'path'
import * as fs from 'fs'

const tmpDir = path.join(__dirname, 'tmp-config-test')
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true })
}

// Mock the 'os' module to redirect CONFIG_PATH in config.ts to our temp directory
vi.mock('os', async (importOriginal) => {
  const original = await importOriginal<typeof import('os')>()
  return {
    ...original,
    homedir: () => require('path').join(__dirname, 'tmp-config-test'),
  }
})

import { loadConfig, saveConfig } from '../../src/config'

describe('Config BOM resilience', () => {
  const configPath = path.join(tmpDir, '.sentinel-oracle', 'config.json')

  beforeAll(() => {
    // Ensure parent directory exists
    fs.mkdirSync(path.dirname(configPath), { recursive: true })
  })

  afterAll(() => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    } catch {}
  })

  it('loads config from file starting with UTF-8 BOM', () => {
    // Write a config JSON starting with BOM: \uFEFF
    const content = '\uFEFF{"githubOwner":"test-owner-bom","githubRepo":"test-repo-bom"}'
    fs.writeFileSync(configPath, content, 'utf8')

    const config = loadConfig()
    expect(config.githubOwner).toBe('test-owner-bom')
    expect(config.githubRepo).toBe('test-repo-bom')
  })

  it('saves config cleanly when it was previously saved with a BOM', () => {
    // Write config with BOM
    const content = '\uFEFF{"githubOwner":"original-owner","githubRepo":"original-repo"}'
    fs.writeFileSync(configPath, content, 'utf8')

    // Call saveConfig to update a value
    saveConfig({ githubRepo: 'updated-repo-bom' })

    // Load again to verify both properties are kept and updated correctly
    const config = loadConfig()
    expect(config.githubOwner).toBe('original-owner')
    expect(config.githubRepo).toBe('updated-repo-bom')
  })
})
