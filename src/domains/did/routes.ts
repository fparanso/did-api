// src/domains/did/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { createDid, resolveDid, deactivate } from './service.js'
import { jwtMiddleware } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const didRouter = new Hono<{ Variables: HonoVariables }>()

const CreateDidSchema = z.object({
  role: z.enum(['subject', 'issuer', 'verifier', 'attester']),
})

// Public — create DID (must be registered before /:did)
didRouter.post('/', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = CreateDidSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const result = await createDid(parsed.data.role)
  return c.json(result, 201)
})

// Protected — get own DID (registered BEFORE /:did to avoid shadowing)
didRouter.get('/me', jwtMiddleware, async c => {
  const did = c.get('did')
  const document = await resolveDid(did)
  return c.json({ did, document })
})

// Public — resolve any DID
didRouter.get('/:did', async c => {
  const document = await resolveDid(c.req.param('did'))
  return c.json({ document })
})

// Protected — deactivate own DID
didRouter.delete('/:did', jwtMiddleware, async c => {
  const callerDid = c.get('did')
  await deactivate(c.req.param('did')!, callerDid)
  return c.json({ success: true })
})
