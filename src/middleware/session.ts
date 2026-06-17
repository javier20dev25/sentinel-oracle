import { Request, Response, NextFunction } from 'express'
import { randomBytes } from 'crypto'
import type { DatabaseStore } from '../storage/database'

const COOKIE_NAME = 'sentinel_session'
const SESSION_TTL_MS = 24 * 60 * 60 * 1000

export interface SessionData {
  id: string
  credentialId: string
  deviceName: string
  csrfToken: string
  userAgent: string
  iat: number
  exp: number
}

let sessionDb: DatabaseStore | null = null

export function initSessionDb(db: DatabaseStore): void {
  sessionDb = db
}

export function requireAuth() {
  return (req: Request, res: Response, next: NextFunction) => {
    const raw = req.signedCookies?.[COOKIE_NAME]
    if (!raw || typeof raw !== 'string') {
      return res.status(401).json({ error: 'Authentication required' })
    }
    let cookieData: { id: string }
    try {
      cookieData = JSON.parse(raw)
    } catch {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session invalid' })
    }
    if (!cookieData.id) {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session invalid' })
    }

    if (!sessionDb) {
      return res.status(500).json({ error: 'Session store not initialized' })
    }

    const dbSession = sessionDb.getSession(cookieData.id)
    if (!dbSession) {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session revoked or expired' })
    }

    sessionDb.touchSession(cookieData.id)

    const session: SessionData = {
      id: dbSession.id,
      credentialId: dbSession.credentialId,
      deviceName: dbSession.deviceName,
      csrfToken: dbSession.csrfToken || '',
      userAgent: dbSession.userAgent || '',
      iat: dbSession.createdAt,
      exp: dbSession.expiresAt,
    }
    ;(req as any).session = session
    next()
  }
}

export function requireCSRF() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next()
    const session = (req as any).session as SessionData | undefined
    if (!session) return res.status(401).json({ error: 'Not authenticated' })
    const headerToken = req.headers['x-csrf-token'] as string
    if (!headerToken || headerToken !== session.csrfToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' })
    }
    next()
  }
}

export function createSessionCookie(credentialId: string, deviceName: string, userAgent?: string) {
  const csrfToken = randomBytes(32).toString('hex')
  if (!sessionDb) {
    throw new Error('Session store not initialized')
  }
  const sessionId = sessionDb.createSession(credentialId, deviceName, SESSION_TTL_MS, csrfToken, userAgent || '')

  return {
    name: COOKIE_NAME,
    value: JSON.stringify({ id: sessionId }),
    options: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: SESSION_TTL_MS,
      signed: true,
    },
  }
}

export function clearSessionCookie() {
  return {
    name: COOKIE_NAME,
    value: '',
    options: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: 0,
    },
  }
}

export function getSessionTTL(): number {
  return SESSION_TTL_MS
}
