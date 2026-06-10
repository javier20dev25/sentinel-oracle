const R = '\x1b[0m'
const GRY = '\x1b[38;2;100;100;100m'

export function logEvent(event: string, detail?: string): void {
  const ts = new Date().toLocaleTimeString()
  const d = detail ? ' — ' + detail : ''
  console.log(` ${GRY}[${ts}]${R} ${event}${GRY}${d}${R}`)
}
