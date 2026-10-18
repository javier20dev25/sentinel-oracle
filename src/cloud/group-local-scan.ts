import { randomUUID, createHash } from 'node:crypto'
import type { Config } from '../config'
import { resolveOracleCloudConnection, assertSecureCloudUrl } from './account'

export interface OracleGroupScanContext {
  baseUrl: string
  groupKey: string
  memberKey: string
  repositoryId: string
}

export interface OracleScanSummary {
  executionId: string
  commitSha: string
  pullRequest: number
  toolVersion: string
  durationMs: number
  findings: { critical: number; high: number; medium: number; low: number }
}

export function resolveOracleGroupScanContext(config: Config): OracleGroupScanContext | null {
  const mode = (process.env.SENTINEL_SCAN_MODE ?? '').trim().toLowerCase()
  const groupKey = (process.env.SENTINEL_GROUP_KEY ?? '').trim()
  const memberKey = (process.env.SENTINEL_MEMBER_KEY ?? '').trim()
  const repositoryId = (process.env.SENTINEL_GROUP_REPOSITORY_ID ?? '').trim()
  const supplied = [groupKey, memberKey, repositoryId].filter(Boolean).length
  if (mode && mode !== 'group' && mode !== 'local') throw new Error('SENTINEL_SCAN_MODE must be either local or group.')
  if (mode === 'local') return null
  if (supplied === 0 && mode !== 'group') return null
  if (mode !== 'group') throw new Error('Set SENTINEL_SCAN_MODE=group to authorize scans against a shared group subscription.')
  if (supplied !== 3) throw new Error('Group scan configuration requires SENTINEL_GROUP_KEY, SENTINEL_MEMBER_KEY, and SENTINEL_GROUP_REPOSITORY_ID together.')
  if (!/^scgrp_[A-Za-z0-9_-]{32,64}$/.test(groupKey) || !/^scmem_[A-Za-z0-9_-]{32,64}$/.test(memberKey) || !/^[0-9a-f-]{36}$/i.test(repositoryId)) {
    throw new Error('Group scan credentials or repository id are invalid.')
  }
  // The stored account is used only as a source of the Cloud host here; its
  // personal bearer token is never sent with group requests or used as identity.
  const cloudBaseUrl = process.env.SENTINEL_CLOUD_URL || resolveOracleCloudConnection(config).baseUrl
  if (!cloudBaseUrl) throw new Error('SENTINEL_CLOUD_URL or a linked Cloud URL is required for group scans.')
  return { baseUrl: assertSecureCloudUrl(cloudBaseUrl), groupKey, memberKey, repositoryId }
}

function requestHeaders(context: OracleGroupScanContext, idempotencyKey?: string) {
  return {
    'Content-Type': 'application/json',
    'x-sentinel-group-key': context.groupKey,
    'x-sentinel-member-key': context.memberKey,
    'x-sentinel-repository-id': context.repositoryId,
    ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
  }
}

async function cloudPost<T>(context: OracleGroupScanContext, path: string, body: unknown, idempotencyKey?: string): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 12_000)
  try {
    const response = await fetch(`${context.baseUrl}${path}`, {
      method: 'POST', headers: requestHeaders(context, idempotencyKey), body: JSON.stringify(body), signal: controller.signal,
    })
    let payload: Record<string, unknown> = {}
    try { payload = await response.json() as Record<string, unknown> } catch { /* invalid responses are rejected below */ }
    if (!response.ok) {
      const code = typeof payload.code === 'string' ? payload.code : `HTTP_${response.status}`
      // Do not forward remote response text that could echo credentials.
      throw new Error(`Cloud group scan request rejected (${code}).`)
    }
    return payload as T
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Cloud group scan request rejected')) throw error
    throw new Error('Cloud group scan authorization or settlement is unavailable.')
  } finally {
    clearTimeout(timer)
  }
}

export async function reserveOracleGroupScan(context: OracleGroupScanContext, pullRequest: number, commitSha: string, scanHash: string, repositoryFullName: string) {
  const key = `oracle-${createHash('sha256').update(`${context.repositoryId}:${pullRequest}:${commitSha}:${scanHash}`).digest('hex')}`
  const result = await cloudPost<{ reservationId?: string; state?: string; reused?: boolean; used?: number; limit?: number }>(
    context,
    '/api/integrations/local-scans/reservations',
    { platform: 'ORACLE', repositoryFullName },
    key,
  )
  if (!result.reservationId) throw new Error('Cloud did not return a scan reservation.')
  return { reservationId: result.reservationId, state: result.state ?? 'RESERVED', reused: result.reused === true, used: result.used, limit: result.limit }
}

export async function settleOracleGroupScan(context: OracleGroupScanContext, reservationId: string, status: 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'CACHED', summary: OracleScanSummary) {
  return cloudPost<{ settled: boolean; state: string; idempotent: boolean; provenance: string }>(
    context,
    `/api/integrations/local-scans/reservations/${encodeURIComponent(reservationId)}/settle`,
    { status, ...summary },
  )
}

export function newOracleExecutionId() { return randomUUID() }
