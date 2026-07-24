import { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import type { DatabaseStore } from '../storage/database'

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://www.gstatic.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: false,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
}

export function corsBlock(req: Request, res: Response, next: NextFunction) {
  const origin = req.headers['origin']
  if (origin) {
    console.log(`[cors] Request from origin: ${origin}`)
    res.setHeader('Access-Control-Allow-Origin', origin)
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*')
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token')
  if (req.method === 'OPTIONS') {
    return res.status(204).end()
  }
  next()
}

export function auditLogger(db: DatabaseStore) {
  return (req: Request, _res: Response, next: NextFunction) => {
    const original = req.path
    if (original.startsWith('/api/')) {
      const detail = `${req.method} ${original} from ${req.ip}`
      db.log('api_request', null, detail)
    }
    next()
  }
}

export function csrfProtection(allowedOrigin: string, db: DatabaseStore) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next()

    const origin = req.headers['origin'] as string | undefined
    const referer = req.headers['referer'] as string | undefined
    if (!origin && !referer) {
      console.log(`[csrf] check: Passed (no origin/referer header) for ${req.method} ${req.path}`)
      return next()
    }

    const source = (origin || referer || '').replace(/\/$/, '')
    const allowed = allowedOrigin.replace(/\/$/, '')

    console.log(`[csrf] check: method=${req.method} path=${req.path} origin=${origin} referer=${referer} source=${source} allowed=${allowed}`)

    if (source.startsWith(allowed)) {
      console.log(`[csrf] check: Passed (source starts with allowedOrigin)`)
      return next()
    }
    if (source.includes('://localhost') || source.includes('://127.0.0.1')) {
      console.log(`[csrf] check: Passed (localhost/127.0.0.1 exception)`)
      return next()
    }
    // Reverse-proxy / funnel compatibility: compare by hostname, ignoring port
    try {
      const a = new URL(allowed)
      const s = new URL(source)
      if (a.protocol === s.protocol && a.hostname === s.hostname) {
        console.log(`[csrf] check: Passed (hostname match, port ${a.port || '443'} vs ${s.port || '443'})`)
        return next()
      }
    } catch {}

    const msg = `Blocked ${req.method} ${req.path} from ${source} (allowedOrigin is ${allowed})`
    console.warn(`[csrf] check: FAILED! ${msg}`)
    db.log('csrf_blocked', null, msg)
    res.status(403).json({ error: 'Cross-origin request blocked' })
  }
}
