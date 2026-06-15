import { Request, Response, NextFunction } from 'express'
import { v4 as uuidv4 } from 'uuid'
import { randomBytes } from 'crypto'

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

export function requireAuth() {
  return (req: Request, res: Response, next: NextFunction) => {
    const raw = req.signedCookies?.[COOKIE_NAME]
    if (!raw || typeof raw !== 'string') {
      return res.status(401).json({ error: 'Authentication required' })
    }
    let session: SessionData
    try {
      session = JSON.parse(raw)
    } catch {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session invalid' })
    }
    if (Date.now() > session.exp) {
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session expired' })
    }
    const ua = req.headers['user-agent'] || ''
    if (session.userAgent && ua && session.userAgent !== ua) {
      return res.status(401).json({ error: 'Session user-agent changed', code: 'UA_MISMATCH' })
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
  const session: SessionData = {
    id: uuidv4(),
    credentialId,
    deviceName,
    csrfToken: randomBytes(32).toString('hex'),
    userAgent: userAgent || '',
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
  }
  return {
    name: COOKIE_NAME,
    value: JSON.stringify(session),
    options: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict' as const,
      path: '/',
      maxAge: SESSION_TTL_MS / 1000,
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
