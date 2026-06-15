import { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import type { DatabaseStore } from '../storage/database'

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://www.gstatic.com"],
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

export function corsBlock(_req: Request, res: Response, next: NextFunction) {
  res.setHeader('Access-Control-Allow-Origin', 'null')
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
    if (!origin && !referer) return next()

    const source = (origin || referer || '').replace(/\/$/, '')
    const allowed = allowedOrigin.replace(/\/$/, '')

    if (source.startsWith(allowed)) return next()
    if (source.includes('://localhost') || source.includes('://127.0.0.1')) return next()

    db.log('csrf_blocked', null, `Blocked ${req.method} ${req.path} from ${source}`)
    res.status(403).json({ error: 'Cross-origin request blocked' })
  }
}
