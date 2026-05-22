import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { createRateLimiter } from '../../../src/shared/middleware/rate-limit'
import { securityHeadersMiddleware } from '../../../src/shared/middleware/security-headers'

describe('rate limiter', () => {
  test('allows requests under the limit', async () => {
    const app = new Hono()
    app.use('*', createRateLimiter(5, 60_000))
    app.get('/', c => c.json({ ok: true }))
    const res = await app.request('http://localhost/')
    expect(res.status).toBe(200)
  })

  test('blocks requests over the limit', async () => {
    const app = new Hono()
    app.use('*', createRateLimiter(2, 60_000))
    app.get('/', c => c.json({ ok: true }))
    // Use a unique IP to avoid interference from other tests
    const ip = '10.0.0.99'
    await app.request('http://localhost/', { headers: { 'x-forwarded-for': ip } })
    await app.request('http://localhost/', { headers: { 'x-forwarded-for': ip } })
    const res = await app.request('http://localhost/', { headers: { 'x-forwarded-for': ip } })
    expect(res.status).toBe(429)
    const body = await res.json()
    expect(body.error).toBe('RATE_LIMITED')
  })
})

describe('security headers', () => {
  test('adds required OWASP security headers', async () => {
    const app = new Hono()
    app.use('*', securityHeadersMiddleware)
    app.get('/', c => c.json({ ok: true }))
    const res = await app.request('http://localhost/')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('strict-transport-security')).toBeTruthy()
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('content-security-policy')).toBeTruthy()
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
  })
})
