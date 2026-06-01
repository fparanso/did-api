// src/shared/middleware/logger.ts
import type { Context, Next } from 'hono'
import { logger } from '../logger.js'
import { recordMetric } from '../metrics.js'

export async function requestLoggerAndMetrics(c: Context, next: Next) {
  const requestId = c.req.header('x-request-id') ?? crypto.randomUUID()
  c.header('x-request-id', requestId)
  c.set('requestId', requestId)

  const start = performance.now()
  const method = c.req.method
  const path = c.req.path

  await next()

  const ms = Math.round(performance.now() - start)
  const status = c.res.status
  const routePath = c.req.routePath ?? path

  // Record metrics per route pattern (or fallback to path)
  recordMetric(method, routePath, status, ms)

  // Log completion of every request in JSON format
  logger.info('Request completed', {
    requestId,
    method,
    path,
    status,
    ms,
  })
}
