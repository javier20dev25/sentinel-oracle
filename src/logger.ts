const R = '\x1b[0m'
const GRY = '\x1b[38;2;100;100;100m'

export function logEvent(event: string, detail?: string): void {
  const ts = new Date().toLocaleTimeString()
  const d = detail ? ' — ' + detail : ''
  console.log(` ${GRY}[${ts}]${R} ${event}${GRY}${d}${R}`)
}

/** Debug-level log; only emitted when SENTINEL_DEBUG=1 keeps default output quiet. */
export function debug(event: string, detail?: string): void {
  if (process.env.SENTINEL_DEBUG !== '1') return
  const ts = new Date().toLocaleTimeString()
  const d = detail ? ' — ' + detail : ''
  console.log(` ${GRY}[${ts}]${R} ${GRY}[debug]${R} ${event}${GRY}${d}${R}`)
}
