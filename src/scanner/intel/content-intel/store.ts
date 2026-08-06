import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { randomBytes } from 'node:crypto'
import Database from 'better-sqlite3'
import {
  applyVerdict,
  revokedRecord,
  signRecord,
  touchRecord,
  verifyRecord,
  type ContentIntelEvidence,
  type ContentIntelRecord,
} from './record'
import type { ContentIntelState } from './state'
import { getScannerVersion } from './scanner-version'

/**
 * Persistence seam for the content-intelligence cache. The Oracle ships an
 * in-process SQLite implementation; the multi-tenant store in the Cloud is a
 * later slice and only needs to implement this interface.
 */
export interface ContentIntelStore {
  lookup(contentId: string): ContentIntelRecord | null
  put(record: ContentIntelRecord): void
  touch(contentId: string, repoKey?: string, now?: number): ContentIntelRecord | null
  record(
    contentId: string,
    state: ContentIntelState,
    evidence: ContentIntelEvidence,
    ctx?: { verified?: boolean; repoKey?: string; now?: number },
  ): ContentIntelRecord
  revoke(contentId: string, now?: number): ContentIntelRecord | null
  close(): void
}

function transitionOnRecord(
  existing: ContentIntelRecord | null,
  contentId: string,
  state: ContentIntelState,
  evidence: ContentIntelEvidence,
  verified: boolean,
  key: Buffer,
  signer: string,
  repoKey?: string,
  now?: number,
): ContentIntelRecord {
  const base = applyVerdict(existing, {
    contentId,
    state,
    scannerVersion: getScannerVersion(),
    verified,
    evidence,
    now,
    repoKey,
  })
  return signRecord(base, key, signer)
}

export class InMemoryContentIntelStore implements ContentIntelStore {
  private readonly records = new Map<string, ContentIntelRecord>()
  private readonly key: Buffer
  private readonly signer: string

  constructor(key: Buffer = Buffer.alloc(32), signer = 'test') {
    this.key = key
    this.signer = signer
  }

  lookup(contentId: string): ContentIntelRecord | null {
    const rec = this.records.get(contentId)
    if (!rec) return null
    if (!verifyRecord(rec, this.key)) {
      this.records.delete(contentId)
      return null
    }
    return rec
  }

  put(record: ContentIntelRecord): void {
    this.records.set(record.contentId, record)
  }

  touch(contentId: string, repoKey?: string, now?: number): ContentIntelRecord | null {
    const rec = this.lookup(contentId)
    if (!rec) return null
    const touched = signRecord(touchRecord(rec, repoKey, now), this.key, this.signer)
    this.put(touched)
    return touched
  }

  record(
    contentId: string,
    state: ContentIntelState,
    evidence: ContentIntelEvidence,
    ctx?: { verified?: boolean; repoKey?: string; now?: number },
  ): ContentIntelRecord {
    const rec = transitionOnRecord(
      this.lookup(contentId),
      contentId,
      state,
      evidence,
      ctx?.verified ?? true,
      this.key,
      this.signer,
      ctx?.repoKey,
      ctx?.now,
    )
    this.put(rec)
    return rec
  }

  revoke(contentId: string, now?: number): ContentIntelRecord | null {
    const rec = this.lookup(contentId)
    if (!rec) return null
    const revoked = signRecord(revokedRecord(rec, getScannerVersion(), now), this.key, this.signer)
    this.put(revoked)
    return revoked
  }

  close(): void {
    this.records.clear()
  }
}

export class SqliteContentIntelStore implements ContentIntelStore {
  private readonly db: Database.Database
  private readonly key: Buffer
  private readonly signer: string

  constructor(dataDir: string, key: Buffer, signer: string) {
    fs.mkdirSync(dataDir, { recursive: true })
    this.db = new Database(path.join(dataDir, 'content-intel.db'))
    this.db.pragma('journal_mode = WAL')
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS content_intel (
        content_id TEXT PRIMARY KEY,
        record_json TEXT NOT NULL,
        state TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `)
    this.key = key
    this.signer = signer
  }

  lookup(contentId: string): ContentIntelRecord | null {
    const row = this.db.prepare('SELECT record_json FROM content_intel WHERE content_id = ?').get(contentId) as
      | { record_json: string }
      | undefined
    if (!row) return null
    let rec: ContentIntelRecord
    try {
      rec = JSON.parse(row.record_json) as ContentIntelRecord
    } catch {
      return null
    }
    if (!verifyRecord(rec, this.key)) return null
    return rec
  }

  put(record: ContentIntelRecord): void {
    this.db
      .prepare('INSERT OR REPLACE INTO content_intel (content_id, record_json, state, updated_at) VALUES (?, ?, ?, ?)')
      .run(record.contentId, JSON.stringify(record), record.state, record.lastSeen)
  }

  touch(contentId: string, repoKey?: string, now?: number): ContentIntelRecord | null {
    const rec = this.lookup(contentId)
    if (!rec) return null
    const touched = signRecord(touchRecord(rec, repoKey, now), this.key, this.signer)
    this.put(touched)
    return touched
  }

  record(
    contentId: string,
    state: ContentIntelState,
    evidence: ContentIntelEvidence,
    ctx?: { verified?: boolean; repoKey?: string; now?: number },
  ): ContentIntelRecord {
    const rec = transitionOnRecord(
      this.lookup(contentId),
      contentId,
      state,
      evidence,
      ctx?.verified ?? true,
      this.key,
      this.signer,
      ctx?.repoKey,
      ctx?.now,
    )
    this.put(rec)
    return rec
  }

  revoke(contentId: string, now?: number): ContentIntelRecord | null {
    const rec = this.lookup(contentId)
    if (!rec) return null
    const revoked = signRecord(revokedRecord(rec, getScannerVersion(), now), this.key, this.signer)
    this.put(revoked)
    return revoked
  }

  close(): void {
    this.db.close()
  }
}

function loadOrCreateKey(dataDir: string): Buffer {
  const keyPath = path.join(dataDir, '.content_intel_key')
  try {
    return fs.readFileSync(keyPath)
  } catch {
    fs.mkdirSync(dataDir, { recursive: true })
    const key = randomBytes(32)
    fs.writeFileSync(keyPath, key, { mode: 0o600 })
    return key
  }
}

let singleton: ContentIntelStore | null | undefined = undefined

/**
 * Default store used when a scan does not inject one. Lazy: it only materializes
 * a SQLite database the first time a content identity is actually seen, so
 * hermetic test suites (mocked registries without dist.integrity) never touch
 * the filesystem. Disable with SENTINEL_CONTENT_INTEL=0.
 */
export function getContentIntelStore(): ContentIntelStore | null {
  if (singleton !== undefined) return singleton
  if (process.env.SENTINEL_CONTENT_INTEL === '0') {
    singleton = null
    return null
  }
  try {
    const dataDir = process.env.SENTINEL_CONTENT_INTEL_DB_DIR || path.join(os.homedir(), '.sentinel-oracle')
    singleton = new SqliteContentIntelStore(dataDir, loadOrCreateKey(dataDir), 'sentinel-oracle')
  } catch {
    singleton = null
  }
  return singleton
}

export function resetContentIntelSingleton(): void {
  singleton = undefined
}
