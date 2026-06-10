import { Request, Response, NextFunction } from 'express'
import type { DatabaseStore } from '../storage/database'

const COOKIE_NAME = 'sentinel_session'
const SESSION_TTL_MS = 24 * 60 * 60 * 1000
const SESSION_IDLE_MS = 30 * 60 * 1000

export function requireAuth(db: DatabaseStore) {
  return (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies?.[COOKIE_NAME]
    if (!sessionId) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    const session = db.getSession(sessionId)
    if (!session) {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session expired or invalid' })
    }
    db.touchSession(sessionId)
    ;(req as any).session = session
    next()
  }
}

export function createSessionCookie(sessionId: string): string {
  return [
    `${COOKIE_NAME}=${sessionId}`,
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${SESSION_TTL_MS / 1000}`,
  ].join('; ')
}

export function clearSessionCookie(): string {
  return [
    `${COOKIE_NAME}=`,
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Path=/',
    'Max-Age=0',
  ].join('; ')
}

export function getSessionTTL(): number {
  return SESSION_TTL_MS
}
