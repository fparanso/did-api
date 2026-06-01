// src/index.ts
import './shared/config.js' // Validate environment immediately
import { Hono } from 'hono'
import { apiReference } from '@scalar/hono-api-reference'
import { AppError } from './shared/errors.js'
import { runMigrations, sql, checkDbHealth } from './shared/db.js'
import { corsMiddleware } from './shared/middleware/cors.js'
import { securityHeadersMiddleware } from './shared/middleware/security-headers.js'
import { createRateLimiter } from './shared/middleware/rate-limit.js'
import { requestLoggerAndMetrics } from './shared/middleware/logger.js'
import { getMetrics } from './shared/metrics.js'
import { authRouter } from './domains/auth/routes.js'
import { didRouter } from './domains/did/routes.js'
import { credentialsRouter } from './domains/credentials/routes.js'
import { presentationRouter } from './domains/presentation/routes.js'
import { trustRouter } from './domains/trust/routes.js'
import { usersRouter } from './domains/users/routes.js'
import { orgsRouter } from './domains/organizations/routes.js'
import { oauthRouter, wellKnownRouter } from './domains/oauth/routes.js'
import { openApiSpec } from './shared/openapi.js'
import type { HonoVariables } from './shared/types.js'

const app = new Hono<{ Variables: HonoVariables }>()

// Global middleware
app.use('*', requestLoggerAndMetrics)
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
app.get('/health', async c => {
  const dbOk = await checkDbHealth()
  const status = dbOk ? 200 : 503
  return c.json({
    status: dbOk ? 'ok' : 'error',
    db: dbOk ? 'ok' : 'error',
    uptime: process.uptime(),
    version: '1.3.0',
  }, status as any)
})

// Metrics endpoint
app.get('/metrics', c => c.json(getMetrics()))

// Routes
app.route('/v1/auth', authRouter)
app.route('/v1/dids', didRouter)
app.route('/v1/credentials', credentialsRouter)
app.route('/v1/presentations', presentationRouter)
app.route('/v1/trust', trustRouter)
// usersRouter is mounted at three prefixes:
//   /v1/auth       — POST /signup, /forgot-password, /reset-password (no path overlap with authRouter)
//   /v1/users      — GET/PATCH /me
//   /v1/admin/users — POST /:id/role
// NOTE: Both authRouter and usersRouter share the /v1/auth prefix. Hono matches in order;
// ensure future routes added to usersRouter don't collide with authRouter paths (/challenge, /verify, /login).
app.route('/v1/auth', usersRouter)
app.route('/v1/users', usersRouter)
app.route('/v1/admin/users', usersRouter)
app.route('/v1/organizations', orgsRouter)
app.route('/oauth', oauthRouter)
app.route('/.well-known', wellKnownRouter)

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

// Startup: run DB migrations
await runMigrations()

let server: any

if (process.env.NODE_ENV !== 'test') {
  const port = parseInt(process.env.PORT ?? '3000')
  server = Bun.serve({
    port,
    fetch: app.fetch,
  })
  console.log(`[server] listening on port ${server.port}`)

  let isShuttingDown = false
  const handleShutdown = async (signal: string) => {
    if (isShuttingDown) return
    isShuttingDown = true
    console.log(`[server] received ${signal}, shutting down gracefully...`)
    
    server.stop()
    await sql.end()
    
    console.log('[server] graceful shutdown complete')
    process.exit(0)
  }

  process.on('SIGTERM', () => handleShutdown('SIGTERM'))
  process.on('SIGINT', () => handleShutdown('SIGINT'))
}

export default process.env.NODE_ENV === 'test'
  ? app
  : {
      port: parseInt(process.env.PORT ?? '3000'),
    }
