// tests/unit/middleware/production-readiness.test.ts
import { describe, test, expect, beforeAll, spyOn } from 'bun:test'
import { Hono } from 'hono'
import { requestLoggerAndMetrics } from '../../../src/shared/middleware/logger.js'
import { getMetrics } from '../../../src/shared/metrics.js'
import { checkDbHealth } from '../../../src/shared/db.js'

describe('Structured logging and metrics middleware', () => {
  test('adds X-Request-ID header and records metrics', async () => {
    const app = new Hono()
    app.use('*', requestLoggerAndMetrics)
    app.get('/test-route', c => c.json({ ok: true }))

    const res = await app.request('http://localhost/test-route')
    expect(res.status).toBe(200)
    expect(res.headers.get('x-request-id')).toBeTruthy()

    const metrics = getMetrics()
    expect(metrics.uptime_ms).toBeGreaterThanOrEqual(0)
    expect(metrics.routes['GET /test-route']).toBeDefined()
    expect(metrics.routes['GET /test-route'].requests).toBe(1)
  })
})

describe('Health endpoint', () => {
  test('returns 200/503 based on database health', async () => {
    // We can import the actual app to test the integrated /health route
    const appModule = await import('../../../src/index.js')
    const app = appModule.app

    // Test health when DB is healthy (or mock checkDbHealth)
    const res = await app.fetch(new Request('http://localhost/health'))
    expect([200, 503]).toContain(res.status)
    const body = await res.json()
    expect(body.status).toBeDefined()
    expect(body.db).toBeDefined()
  })
})

describe('Metrics endpoint', () => {
  test('returns metrics JSON', async () => {
    const appModule = await import('../../../src/index.js')
    const app = appModule.app

    const res = await app.fetch(new Request('http://localhost/metrics'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.uptime_ms).toBeGreaterThanOrEqual(0)
    expect(body.routes).toBeDefined()
  })
})
