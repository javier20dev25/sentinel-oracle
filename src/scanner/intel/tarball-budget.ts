/**
 * Network budget for tarball scanning.
 *
 * Bounds how much registry work a single PR analysis can trigger, so a PR that
 * adds 120 packages degrades gracefully (scan the most relevant, stop) instead
 * of running an unbounded download burst. A fixed cap (e.g. "scan 2 added
 * deps") does not scale; a budget does: work continues until the budget runs
 * out, then stops.
 *
 * Budget dimensions (env-overridable):
 *
 *   SENTINEL_TARBALL_BUDGET_PACKAGES     max packages scanned      (default 20)
 *   SENTINEL_TARBALL_BUDGET_BYTES        max total tarball bytes   (default 50 MB)
 *   SENTINEL_TARBALL_BUDGET_TIME         max wall-clock ms         (default 60 s)
 *   SENTINEL_TARBALL_BUDGET_CONCURRENCY  max parallel fetches      (default 2)
 */
export const DEFAULT_TARBALL_BUDGET = {
  maxPackages: 20,
  maxBytes: 50 * 1024 * 1024,
  maxTimeMs: 60_000,
  maxConcurrency: 2,
}

export interface TarballBudgetOptions {
  maxPackages?: number
  maxBytes?: number
  maxTimeMs?: number
  maxConcurrency?: number
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
  readonly maxPackages: number
  readonly maxBytes: number
  readonly maxTimeMs: number
  readonly maxConcurrency: number

  private spentPackages = 0
  private spentBytes = 0
  private readonly startedAt = Date.now()

  constructor(opts: TarballBudgetOptions = {}) {
    const e = process.env
    this.maxPackages = num(opts.maxPackages, e.SENTINEL_TARBALL_BUDGET_PACKAGES, DEFAULT_TARBALL_BUDGET.maxPackages)
    this.maxBytes = num(opts.maxBytes, e.SENTINEL_TARBALL_BUDGET_BYTES, DEFAULT_TARBALL_BUDGET.maxBytes)
    this.maxTimeMs = num(opts.maxTimeMs, e.SENTINEL_TARBALL_BUDGET_TIME, DEFAULT_TARBALL_BUDGET.maxTimeMs)
    this.maxConcurrency = Math.max(1, num(opts.maxConcurrency, e.SENTINEL_TARBALL_BUDGET_CONCURRENCY, DEFAULT_TARBALL_BUDGET.maxConcurrency))
  }

  /** Current spending snapshot (for reporting / tests). */
  get spent() {
    return { packages: this.spentPackages, bytes: this.spentBytes, ms: Date.now() - this.startedAt }
  }

  /** True while any budget dimension remains. */
  remaining(): boolean {
    return (
      this.spentPackages < this.maxPackages &&
      this.spentBytes < this.maxBytes &&
      Date.now() - this.startedAt < this.maxTimeMs
    )
  }

  /** Account one started scan (consumes a package slot). */
  spendPackage(): void {
    this.spentPackages++
  }

  /** Account downloaded bytes (called by the downloader after a successful fetch). */
  accountBytes(bytes: number): void {
    if (bytes > 0) this.spentBytes += bytes
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
    const results: Array<{ item: T; value: R | undefined }> = []
    let next = 0
    const runner = async () => {
      while (next < items.length) {
        if (!this.remaining()) break
        const idx = next++
        this.spendPackage()
        try {
          results.push({ item: items[idx], value: await worker(items[idx]) })
        } catch {
          results.push({ item: items[idx], value: undefined })
        }
      }
    }
    const runners = Array.from({ length: Math.max(1, this.maxConcurrency) }, () => runner())
    await Promise.all(runners)
    return results
  }
}
