import rateLimit from 'express-rate-limit'
import type { DatabaseStore } from '../storage/database'

export function authRateLimiter(maxRequests: number, windowMs: number) {
  return rateLimit({
    windowMs,
    max: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts', retryAfter: windowMs / 1000 },
  })
}

export function apiRateLimiter(maxRequests: number, windowMs: number) {
  return rateLimit({
    windowMs,
    max: maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
  })
}
