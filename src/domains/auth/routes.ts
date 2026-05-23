// src/domains/auth/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { requestChallenge, verifyChallenge } from './service.js'
import { loginUser } from '../users/service.js'
import type { HonoVariables } from '../../shared/types.js'

export const authRouter = new Hono<{ Variables: HonoVariables }>()

const ChallengeSchema = z.object({ did: z.string().min(1) })
const VerifySchema = z.object({
  did: z.string().min(1),
  challengeId: z.string().uuid(),
  signature: z.string().min(1),
})

authRouter.post('/challenge', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = ChallengeSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const result = await requestChallenge(parsed.data.did)
  return c.json(result)
})

authRouter.post('/verify', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = VerifySchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const token = await verifyChallenge(parsed.data.did, parsed.data.challengeId, parsed.data.signature)
  return c.json({ token })
})

authRouter.post('/login', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = z.object({
    email: z.string().email(),
    password: z.string().min(1),
  }).safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const result = await loginUser(parsed.data.email, parsed.data.password)
  return c.json(result)
})
