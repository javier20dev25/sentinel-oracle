import rateLimit from 'express-rate-limit'
import type { DatabaseStore } from '../storage/database'

const isTestMode = () => process.env.SENTINEL_TEST_MODE === '1'

export function authRateLimiter(maxRequests: number, windowMs: number) {
  return rateLimit({
    windowMs,
    max: isTestMode() ? 0 : maxRequests,
    skip: () => isTestMode(),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts', retryAfter: windowMs / 1000 },
  })
}

export function apiRateLimiter(maxRequests: number, windowMs: number) {
  return rateLimit({
    windowMs,
    max: isTestMode() ? 0 : maxRequests,
    skip: () => isTestMode(),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
  })
}
