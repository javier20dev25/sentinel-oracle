import { vi, describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import * as path from 'path'
import * as fs from 'fs'

const tmpDir = path.join(__dirname, 'tmp-cloud-config-test')
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true })
}

// Mock the 'os' module to redirect CONFIG_PATH in config.ts to our temp directory
vi.mock('os', async (importOriginal) => {
  const original = await importOriginal<typeof import('os')>()
  return {
    ...original,
    homedir: () => require('path').join(__dirname, 'tmp-cloud-config-test'),
  }
})

import { loadConfig, saveConfig } from '../../src/config'

const configPath = path.join(tmpDir, '.sentinel-oracle', 'config.json')

beforeAll(() => {
  fs.mkdirSync(path.dirname(configPath), { recursive: true })
})

afterEach(() => {
  vi.unstubAllEnvs()
  try {
    fs.rmSync(configPath, { force: true })
  } catch {}
})

afterAll(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  } catch {}
})

describe('config: cloud connection settings', () => {
  it('defaults cloudApiUrl/cloudApiToken to empty when env is unset', () => {
    const config = loadConfig()
    expect(config.cloudApiUrl).toBe('')
    expect(config.cloudApiToken).toBe('')
  })

  it('defaults cloudApiUrl/cloudApiToken from SENTINEL_CLOUD_URL / SENTINEL_CLOUD_API_TOKEN', () => {
    vi.stubEnv('SENTINEL_CLOUD_URL', 'https://cloud.example')
    vi.stubEnv('SENTINEL_CLOUD_API_TOKEN', 'secret-token-123')
    const config = loadConfig()
    expect(config.cloudApiUrl).toBe('https://cloud.example')
    expect(config.cloudApiToken).toBe('secret-token-123')
  })

  it('persists cloudApiUrl/cloudApiToken through saveConfig (save/load round trip)', () => {
    saveConfig({ githubOwner: 'keep-me', cloudApiUrl: 'https://cloud.example', cloudApiToken: 'token-abc' })
    const config = loadConfig()
    expect(config.githubOwner).toBe('keep-me')
    expect(config.cloudApiUrl).toBe('https://cloud.example')
    expect(config.cloudApiToken).toBe('token-abc')
  })

  it('still excludes encryptionKey/cookieSecret/hmacSeed from saveConfig', () => {
    saveConfig({ cookieSecret: 'should-not-persist', cloudApiUrl: 'https://cloud.example' })
    const config = loadConfig()
    expect(config.cloudApiUrl).toBe('https://cloud.example')
    expect(config.cookieSecret).not.toBe('should-not-persist')
  })
})
