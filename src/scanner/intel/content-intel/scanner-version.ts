let cached: string | null = null

/**
 * Version of the scanner+rules that produced a verdict. Records are revalidated
 * (re-scanned) whenever this changes, so a rules upgrade never replays findings
 * computed by an older engine.
 */
export function getScannerVersion(): string {
  if (cached) return cached
  if (process.env.SENTINEL_CONTENT_INTEL_VERSION) {
    cached = process.env.SENTINEL_CONTENT_INTEL_VERSION
    return cached
  }
  try {
    // src/scanner/intel/content-intel/scanner-version.ts -> repo root package.json
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cached = String(require('../../../../package.json').version ?? 'dev')
  } catch {
    cached = 'dev'
  }
  return cached
}

export const CONTENT_INTEL_SCANNER_VERSION = getScannerVersion()
