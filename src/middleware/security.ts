import { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import type { DatabaseStore } from '../storage/database'

export function securityHeaders() {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
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
