import type { Context, Next } from 'hono'
import { Errors } from '../errors.js'

const store = new Map<string, { count: number; resetAt: number }>()

let _disabled = false
export function setRateLimitDisabled(disabled: boolean): void {
  _disabled = disabled
}

export function createRateLimiter(maxRequests: number, windowMs: number) {
  return async (c: Context, next: Next) => {
    if (_disabled) return next()
    const ip = c.req.header('x-forwarded-for') ?? c.req.header('x-real-ip') ?? 'unknown'
    const now = Date.now()
    const entry = store.get(ip)

    if (!entry || entry.resetAt < now) {
      store.set(ip, { count: 1, resetAt: now + windowMs })
      return next()
    }
    if (entry.count >= maxRequests) {
      const err = Errors.RATE_LIMITED()
      return c.json({ error: err.code, message: err.message, status: 429 }, 429)
    }
    entry.count++
    return next()
  }
}
