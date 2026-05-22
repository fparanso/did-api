// src/domains/users/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { timingSafeEqual } from 'crypto'
import {
  createUser,
  requestPasswordReset,
  resetPassword,
  getProfile,
  updateProfile,
  upgradeRole,
} from './service.js'
import { jwtMiddleware } from '../auth/middleware.js'
import type { HonoVariables, Role } from '../../shared/types.js'

export const usersRouter = new Hono<{ Variables: HonoVariables }>()

const SignupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1),
  organizationName: z.string().optional(),
})

const ForgotSchema = z.object({ email: z.string().email() })

const ResetSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(8),
})

const UpdateProfileSchema = z.object({
  name: z.string().min(1).optional(),
  organizationName: z.string().optional(),
})

const UpgradeRoleSchema = z.object({
  role: z.enum(['subject', 'issuer', 'verifier', 'attester']),
})

// POST /v1/auth/signup
usersRouter.post('/signup', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = SignupSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const { email, password, name, organizationName } = parsed.data
  const result = await createUser(email, password, name, organizationName)
  return c.json(result, 201)
})

// POST /v1/auth/forgot-password
usersRouter.post('/forgot-password', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = ForgotSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const { resetToken } = await requestPasswordReset(parsed.data.email)
  const response: Record<string, unknown> = {
    message: 'If that email is registered, a reset token has been issued.',
  }
  if (resetToken) response.resetToken = resetToken
  return c.json(response)
})

// POST /v1/auth/reset-password
usersRouter.post('/reset-password', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = ResetSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  await resetPassword(parsed.data.token, parsed.data.newPassword)
  return c.json({ message: 'Password updated successfully. Please log in again.' })
})

// GET /v1/users/me
usersRouter.get('/me', jwtMiddleware, async c => {
  const profile = await getProfile(c.get('did'))
  return c.json(profile)
})

// PATCH /v1/users/me
usersRouter.patch('/me', jwtMiddleware, async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = UpdateProfileSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const profile = await updateProfile(c.get('did'), parsed.data)
  return c.json(profile)
})

// POST /v1/admin/users/:id/role
usersRouter.post('/:id/role', async c => {
  const secret = c.req.header('x-admin-secret') ?? ''
  const expected = process.env.ADMIN_SECRET ?? ''
  const secretBuf = Buffer.from(secret)
  const expectedBuf = Buffer.from(expected)
  const valid =
    secret.length > 0 &&
    secretBuf.length === expectedBuf.length &&
    timingSafeEqual(secretBuf, expectedBuf)

  if (!valid) {
    return c.json({ error: 'UNAUTHORIZED', message: 'Invalid or missing admin secret', status: 401 }, 401)
  }

  const body = await c.req.json().catch(() => ({}))
  const parsed = UpgradeRoleSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  await upgradeRole(c.req.param('id'), parsed.data.role as Role)
  return c.json({ success: true })
})
