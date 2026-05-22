// src/index.ts
import { Hono } from 'hono'
import { apiReference } from '@scalar/hono-api-reference'
import { AppError } from './shared/errors.js'
import { runMigrations, sql } from './shared/db.js'
import { initContextLoader, setDidResolver } from './shared/jsonld/loader.js'
import { corsMiddleware } from './shared/middleware/cors.js'
import { securityHeadersMiddleware } from './shared/middleware/security-headers.js'
import { createRateLimiter } from './shared/middleware/rate-limit.js'
import { authRouter } from './domains/auth/routes.js'
import { didRouter } from './domains/did/routes.js'
import { credentialsRouter } from './domains/credentials/routes.js'
import { presentationRouter } from './domains/presentation/routes.js'
import { trustRouter } from './domains/trust/routes.js'
import { findDid } from './domains/did/repository.js'
import { openApiSpec } from './shared/openapi.js'
import type { HonoVariables } from './shared/types.js'

const app = new Hono<{ Variables: HonoVariables }>()

// Global middleware
app.use('*', corsMiddleware)
app.use('*', securityHeadersMiddleware)
app.use('*', createRateLimiter(100, 60_000))

// Body size limit: 64KB
app.use('*', async (c, next) => {
  const contentLength = c.req.header('content-length')
  if (contentLength && parseInt(contentLength) > 65536) {
    return c.json(
      { error: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds 64KB', status: 413 },
      413
    )
  }
  return next()
})

// Health check
app.get('/health', c => c.json({ status: 'ok' }))

// Routes
app.route('/v1/auth', authRouter)
app.route('/v1/dids', didRouter)
app.route('/v1/credentials', credentialsRouter)
app.route('/v1/presentations', presentationRouter)
app.route('/v1/trust', trustRouter)

// OpenAPI Spec & Scalar Reference UI
app.get('/openapi.json', c => c.json(openApiSpec))
app.get(
  '/docs',
  apiReference({
    theme: 'purple',
    spec: {
      url: '/openapi.json',
    },
  })
)

// Global error handler
app.onError((err, c) => {
  if (err instanceof AppError) {
    return c.json(
      { error: err.code, message: err.message, status: err.status },
      err.status as any
    )
  }
  // Don't leak internal error details in production
  const isDev = process.env.NODE_ENV !== 'production'
  console.error('[error]', err.message)
  return c.json(
    {
      error: 'INTERNAL_ERROR',
      message: isDev ? err.message : 'An internal error occurred',
      status: 500,
    },
    500
  )
})

// Startup: run DB migrations, load JSON-LD contexts, wire DID resolver
await runMigrations()
await initContextLoader()

setDidResolver(async (did: string) => {
  const record = await findDid(did)
  if (!record || record.deactivatedAt) {
    throw new AppError('DID_NOT_FOUND', `DID ${did} not found`, 404)
  }
  return record.document
})

export default {
  port: parseInt(process.env.PORT ?? '3000'),
  fetch: app.fetch,
}
