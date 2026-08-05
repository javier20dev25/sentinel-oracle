/**
 * Network budget for tarball scanning.
 *
 * Bounds how much registry work a single PR analysis can trigger, so a PR that
 * adds 120 packages degrades gracefully (scan the most relevant, stop) instead
 * of running an unbounded download burst. A fixed cap (e.g. "scan 2 added
 * deps") does not scale; a budget does: work continues until the budget runs
 * out, then stops.
 *
 * The budget is governed by REAL resources — bytes and wall-clock time — not an
 * arbitrary package count:
 *
 *   SENTINEL_TARBALL_BUDGET_BYTES        max total tarball bytes   (default 50 MB)
 *   SENTINEL_TARBALL_BUDGET_TIME         max wall-clock ms         (default 60 s)
 *   SENTINEL_TARBALL_BUDGET_CONCURRENCY  max parallel fetches      (default 2)
 *   SENTINEL_TARBALL_BUDGET_PACKAGES     safety ceiling for work items (default 200)
 *
 * `packages` is deliberately NOT a truncation dimension: it only guards the
 * queue against a pathological manifest (e.g. 10k entries) and defaults high
 * enough to never bind on a realistic PR. Truncation is driven by bytes/time.
 *
 * Bytes are HARD: `download()` reserves the expected size (from Content-Length)
 * BEFORE reading the response body. If the reservation exceeds the remaining
 * budget, the body is never consumed — so even under concurrency,
 * spent+reserved can never overshoot maxBytes. Time is soft under concurrency
 * (in-flight downloads finish, no new ones start).
 *
 * Each budget instance also collects per-scan telemetry (requested/scanned,
 * cache hits, download/analysis ms, bytes, reason truncated) that surfaces on
 * the IntelReport so dashboards can show "80% of the time goes to downloading"
 * and "95% of packages were cache hits".
 */
import { randomUUID } from 'node:crypto'

export type BudgetExhaustedReason = 'BYTE_BUDGET' | 'TIME_BUDGET' | 'SAFETY_CEILING' | null

export const DEFAULT_TARBALL_BUDGET = {
  safetyCeiling: 200,
  maxBytes: 50 * 1024 * 1024,
  maxTimeMs: 60_000,
  maxConcurrency: 2,
}

export interface TarballBudgetOptions {
  safetyCeiling?: number
  /** Legacy alias for safetyCeiling. */
  maxPackages?: number
  maxBytes?: number
  maxTimeMs?: number
  maxConcurrency?: number
}

/**
 * Opaque token returned by `reserve()`. Call `settle(actualBytes)` once the
 * transfer finished, or `cancel()` if it never happened.
 */
export interface BudgetReservation {
  settle(actualBytes: number): void
  cancel(): void
}

export interface BudgetSnapshot {
  spentPackages: number
  spentBytes: number
  elapsedMs: number
  remainingBytes: number
  remainingTimeMs: number
  remainingWorkers: number
}

export interface ScanTelemetry {
  scanId: string
  packagesRequested: number
  packagesScanned: number
  cacheHits: number
  cacheMisses: number
  downloadMs: number
  analysisMs: number
  bytesDownloaded: number
  reasonTruncated: BudgetExhaustedReason
}

function num(v: number | undefined, envValue: string | undefined, fallback: number): number {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return v
  if (envValue !== undefined && envValue !== '') {
    const n = parseInt(envValue, 10)
    if (Number.isFinite(n) && n >= 0) return n
  }
  return fallback
}

export class TarballBudget {
  readonly safetyCeiling: number
  readonly maxBytes: number
  readonly maxTimeMs: number
  readonly maxConcurrency: number

  private spentPackages = 0
  private spentBytes = 0
  private reservedBytes = 0
  private activeWorkers = 0
  private reason: BudgetExhaustedReason = null
  private readonly startedAt = Date.now()
  private readonly scanId = randomUUID()

  private requested = 0
  private scanned = 0
  private cacheHits = 0
  private cacheMisses = 0
  private downloadMs = 0
  private workerMs = 0

  constructor(opts: TarballBudgetOptions = {}) {
    const e = process.env
    const ceiling = num(opts.safetyCeiling, e.SENTINEL_TARBALL_BUDGET_PACKAGES, DEFAULT_TARBALL_BUDGET.safetyCeiling)
    this.safetyCeiling = num(opts.maxPackages, undefined, ceiling)
    this.maxBytes = num(opts.maxBytes, e.SENTINEL_TARBALL_BUDGET_BYTES, DEFAULT_TARBALL_BUDGET.maxBytes)
    this.maxTimeMs = num(opts.maxTimeMs, e.SENTINEL_TARBALL_BUDGET_TIME, DEFAULT_TARBALL_BUDGET.maxTimeMs)
    this.maxConcurrency = Math.max(1, num(opts.maxConcurrency, e.SENTINEL_TARBALL_BUDGET_CONCURRENCY, DEFAULT_TARBALL_BUDGET.maxConcurrency))
  }

  /** Current spending snapshot (for reporting / tests). */
  get spent() {
    return { packages: this.spentPackages, bytes: this.spentBytes, ms: Date.now() - this.startedAt }
  }

  /** Why scanning stopped early (first cause wins), or null when it completed. */
  get reasonTruncated(): BudgetExhaustedReason {
    return this.reason
  }

  private setReason(r: Exclude<BudgetExhaustedReason, null>): void {
    if (this.reason === null) this.reason = r
  }

  remainingBytes(): number {
    return Math.max(0, this.maxBytes - this.spentBytes - this.reservedBytes)
  }

  remainingTimeMs(): number {
    return Math.max(0, this.maxTimeMs - (Date.now() - this.startedAt))
  }

  remainingWorkers(): number {
    return Math.max(0, this.maxConcurrency - this.activeWorkers)
  }

  /** True while the scan may start new work (time and bytes remain). Pure check. */
  remaining(): boolean {
    return this.remainingTimeMs() > 0 && this.remainingBytes() > 0
  }

  /**
   * Reserve `bytes` of download budget. Returns null (and never lets the caller
   * start) when the reservation would overshoot the remaining budget — the hard
   * byte gate. On success the caller must settle or cancel the reservation.
   */
  reserve(bytes: number): BudgetReservation | null {
    if (!Number.isFinite(bytes) || bytes < 0) return null
    if (bytes === 0) return this.remaining() ? this.noopReservation() : null
    if (!this.remaining()) {
      this.setReason(this.remainingTimeMs() <= 0 ? 'TIME_BUDGET' : 'BYTE_BUDGET')
      return null
    }
    if (bytes > this.remainingBytes()) {
      this.setReason('BYTE_BUDGET')
      return null
    }
    this.reservedBytes += bytes
    return {
      settle: (actual) => {
        this.reservedBytes -= bytes
        if (actual > 0) this.spentBytes += actual
      },
      cancel: () => {
        this.reservedBytes -= bytes
      },
    }
  }

  /** Account a finished download: settle its reservation, record ms + scanned. */
  recordDownload(actualBytes: number, ms: number, reservation: BudgetReservation | null): void {
    reservation?.settle(actualBytes)
    this.downloadMs += Math.max(0, ms)
    this.scanned++
    this.cacheMisses++
  }

  /** Cache hit placeholder (Fase 2: global intelligence cache) — no download ran. */
  recordCacheHit(): void {
    this.cacheHits++
  }

  /** Account total worker wall-clock (includes download time). */
  recordWorker(ms: number): void {
    this.workerMs += Math.max(0, ms)
  }

  /** Number of items handed to `map()` for telemetry. */
  recordRequested(n: number): void {
    this.requested += n
  }

  snapshot(): BudgetSnapshot {
    return {
      spentPackages: this.spentPackages,
      spentBytes: this.spentBytes,
      elapsedMs: Date.now() - this.startedAt,
      remainingBytes: this.remainingBytes(),
      remainingTimeMs: this.remainingTimeMs(),
      remainingWorkers: this.remainingWorkers(),
    }
  }

  telemetry(): ScanTelemetry {
    return {
      scanId: this.scanId,
      packagesRequested: this.requested,
      packagesScanned: this.scanned,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      downloadMs: Math.round(this.downloadMs),
      analysisMs: Math.round(Math.max(0, this.workerMs - this.downloadMs)),
      bytesDownloaded: this.spentBytes,
      reasonTruncated: this.reason,
    }
  }

  private noopReservation(): BudgetReservation {
    return { settle: () => {}, cancel: () => {} }
  }

  /**
   * Run `worker` over `items` with bounded concurrency, stopping as soon as the
   * budget is exhausted. Results preserve item order; `value` is undefined when
   * the worker returned undefined or threw. Items that never started (budget
   * exhausted) are simply not included.
   */
  async map<T, R>(
    items: T[],
    worker: (item: T) => Promise<R | undefined>,
  ): Promise<Array<{ item: T; value: R | undefined }>> {
    this.recordRequested(items.length)
    const results: Array<{ item: T; value: R | undefined }> = []
    let next = 0
    const runner = async () => {
      while (next < items.length) {
        if (this.spentPackages >= this.safetyCeiling) {
          this.setReason('SAFETY_CEILING')
          break
        }
        if (!this.remaining()) {
          this.setReason(this.remainingTimeMs() <= 0 ? 'TIME_BUDGET' : 'BYTE_BUDGET')
          break
        }
        const idx = next++
        this.spentPackages++
        this.activeWorkers++
        const w0 = performance.now()
        try {
          results.push({ item: items[idx], value: await worker(items[idx]) })
        } catch {
          results.push({ item: items[idx], value: undefined })
        } finally {
          this.recordWorker(performance.now() - w0)
          this.activeWorkers--
        }
      }
    }
    const runners = Array.from({ length: Math.max(1, this.maxConcurrency) }, () => runner())
    await Promise.all(runners)
    return results
  }
}

export function mergeTelemetry(a: ScanTelemetry, b: ScanTelemetry): ScanTelemetry {
  return {
    scanId: a.scanId || b.scanId,
    packagesRequested: a.packagesRequested + b.packagesRequested,
    packagesScanned: a.packagesScanned + b.packagesScanned,
    cacheHits: a.cacheHits + b.cacheHits,
    cacheMisses: a.cacheMisses + b.cacheMisses,
    downloadMs: a.downloadMs + b.downloadMs,
    analysisMs: a.analysisMs + b.analysisMs,
    bytesDownloaded: a.bytesDownloaded + b.bytesDownloaded,
    reasonTruncated: a.reasonTruncated ?? b.reasonTruncated,
  }
}
