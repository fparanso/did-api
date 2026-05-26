// src/domains/presentation/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { deriveSelectivePresentation, verifyVp, verifyPresentationById, getPresentation } from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const presentationRouter = new Hono<{ Variables: HonoVariables }>()

const DeriveSchema = z.object({
  credentialId: z.string().min(1),
  revealedClaims: z.array(z.string()).min(1),
})

const VerifySchema = z.object({
  presentation: z.record(z.unknown()).optional(),
  presentationId: z.string().optional(),
}).refine(d => d.presentation !== undefined || d.presentationId !== undefined, {
  message: 'Either presentation or presentationId must be provided',
})

presentationRouter.post(
  '/derive',
  jwtMiddleware,
  requireRole('subject'),
  async c => {
    const body = await c.req.json().catch(() => ({}))
    const parsed = DeriveSchema.safeParse(body)
    if (!parsed.success) {
      return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
    }
    const result = await deriveSelectivePresentation(
      c.get('did'),
      parsed.data.credentialId,
      parsed.data.revealedClaims
    )
    return c.json(result, 201)
  }
)

presentationRouter.post(
  '/verify',
  jwtMiddleware,
  requireRole('verifier'),
  async c => {
    const body = await c.req.json().catch(() => ({}))
    const parsed = VerifySchema.safeParse(body)
    if (!parsed.success) {
      return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
    }

    if (parsed.data.presentationId) {
      const result = await verifyPresentationById(parsed.data.presentationId)
      return c.json(result)
    }

    const result = await verifyVp(parsed.data.presentation!, c.get('did'))
    return c.json(result)
  }
)

presentationRouter.get('/:id', jwtMiddleware, requireRole('subject'), async c => {
  const id = c.req.param('id') ?? ''
  const record = await getPresentation(id, c.get('did'))
  return c.json(record)
})
