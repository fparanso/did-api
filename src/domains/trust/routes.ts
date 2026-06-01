// src/domains/trust/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import {
  attestIssuer,
  getTrustedIssuers,
  isIssuerTrusted,
  revokeIssuerAttestation,
} from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const trustRouter = new Hono<{ Variables: HonoVariables }>()

const AttestSchema = z.object({
  issuerDid: z.string().min(1),
  expiresAt: z.string().datetime().optional(),
})

// Public reads
trustRouter.get('/issuers', async c => {
  const issuers = await getTrustedIssuers()
  return c.json({ issuers })
})

trustRouter.get('/issuers/:did', async c => {
  const trusted = await isIssuerTrusted(c.req.param('did'))
  return c.json({ trusted })
})

// Protected writes — attester only
trustRouter.post('/attest', jwtMiddleware, requireRole('attester'), async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = AttestSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const attesterDid = c.get('did')
  const expiresAt = parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : undefined
  const result = await attestIssuer(attesterDid, parsed.data.issuerDid, expiresAt)
  return c.json(result, 201)
})

trustRouter.post('/attest/:id/revoke', jwtMiddleware, requireRole('attester'), async c => {
  await revokeIssuerAttestation(c.req.param('id')!, c.get('did'))
  return c.json({ success: true })
})
