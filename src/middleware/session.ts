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

let noAuthMode = false
export function setNoAuthMode(v: boolean): void {
  noAuthMode = v
}
export function isNoAuthMode(): boolean {
  return noAuthMode
}

export function requireAuth() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (noAuthMode) return next()
    const raw = req.signedCookies?.[COOKIE_NAME]
    console.log(`[auth] requireAuth: path=${req.path} hasCookie=${!!raw} cookieType=${typeof raw} allSignedCookies=${Object.keys(req.signedCookies || {}).join(',')}`)
    if (!raw || typeof raw !== 'string') {
      if (raw === false) console.warn(`[auth] requireAuth: cookie signature INVALID for ${req.path}`)
      return res.status(401).json({ error: 'Authentication required' })
    }
    let cookieData: { id: string }
    try {
      cookieData = JSON.parse(raw)
    } catch (parseErr) {
      console.warn(`[auth] requireAuth: cookie parse FAILED raw="${raw}" error=${parseErr}`)
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session invalid' })
    }
    if (!cookieData.id) {
      console.warn(`[auth] requireAuth: cookie missing id field`)
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session invalid' })
    }

    if (!sessionDb) {
      return res.status(500).json({ error: 'Session store not initialized' })
    }

    const dbSession = sessionDb.getSession(cookieData.id)
    if (!dbSession) {
      console.warn(`[auth] requireAuth: session not found in DB for id=${cookieData.id?.slice(0, 16)}`)
      res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
      return res.status(401).json({ error: 'Session revoked or expired' })
    }
    console.log(`[auth] requireAuth: PASSED device=${dbSession.deviceName}`)

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
