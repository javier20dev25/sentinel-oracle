import { randomBytes, scryptSync, timingSafeEqual } from 'crypto'

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex')
  const key = scryptSync(password, salt, 32).toString('hex')
  return salt + ':' + key
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':')
  if (parts.length !== 2) return false
  const [salt, key] = parts
  const derived = scryptSync(password, salt, 32).toString('hex')
  if (derived.length !== key.length) return false
  return timingSafeEqual(Buffer.from(derived), Buffer.from(key))
}
