// src/domains/credentials/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import {
  issueCredential,
  getCredential,
  listCredentials,
  revokeCredentialById,
  getCredentialStatus,
  buildStatusList,
} from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import { createRateLimiter } from '../../shared/middleware/rate-limit.js'
import type { HonoVariables } from '../../shared/types.js'

export const credentialsRouter = new Hono<{ Variables: HonoVariables }>()

const IssueSchema = z.object({
  subjectDid: z.string().min(1),
  credentialType: z.array(z.string()).min(1),
  claims: z.record(z.unknown()),
  expiresAt: z.string().datetime().optional(),
})

// Public — Token Status List 1.0
credentialsRouter.get('/status-lists/:id', async c => {
  const jwt = await buildStatusList(c.req.param('id'))
  return new Response(jwt, {
    headers: { 'Content-Type': 'application/statuslist+jwt' },
  })
})

// Public — status check (before protected routes)
credentialsRouter.get('/:id/status', async c => {
  const result = await getCredentialStatus(c.req.param('id'))
  return c.json(result)
})

// Protected — list all (issuer only)
credentialsRouter.get('/', jwtMiddleware, requireRole('issuer'), async c => {
  const records = await listCredentials(c.get('did'))
  return c.json({ credentials: records })
})

// Protected — issue (issuer only, strict rate limit)
credentialsRouter.post(
  '/issue',
  jwtMiddleware,
  requireRole('issuer'),
  createRateLimiter(10, 60_000),
  async c => {
    const body = await c.req.json().catch(() => ({}))
    const parsed = IssueSchema.safeParse(body)
    if (!parsed.success) {
      return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
    }
    const { subjectDid, credentialType, claims, expiresAt } = parsed.data
    const signedVc = await issueCredential(
      c.get('did'),
      subjectDid,
      credentialType,
      claims,
      expiresAt ? new Date(expiresAt) : undefined
    )
    return c.json(signedVc, 201)
  }
)

// Protected — fetch by ID (issuer or subject)
credentialsRouter.get('/:id', jwtMiddleware, async c => {
  const record = await getCredential(c.req.param('id'), c.get('did'))
  return c.json(record)
})

// Protected — revoke (issuer only)
credentialsRouter.post('/:id/revoke', jwtMiddleware, requireRole('issuer'), async c => {
  await revokeCredentialById(c.req.param('id'), c.get('did'))
  return c.json({ success: true })
})
