// src/domains/organizations/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import {
  createOrg,
  getOrg,
  getOrgMembers,
  inviteMember,
  acceptInvite,
  updateMemberRole,
  removeMember,
  deleteOrg,
} from './service.js'
import { jwtMiddleware } from '../auth/middleware.js'
import type { HonoVariables, OrgMemberRole, Role } from '../../shared/types.js'

export const orgsRouter = new Hono<{ Variables: HonoVariables }>()

const CreateOrgSchema = z.object({
  name: z.string().min(1),
  slug: z.string().regex(/^[a-z0-9-]+$/).optional(),
  role: z.enum(['issuer', 'attester', 'verifier']),
})

const InviteSchema = z.union([
  z.object({ email: z.string().email(), role: z.enum(['admin', 'member']) }),
  z.object({ did: z.string().min(1), role: z.enum(['admin', 'member']) }),
])

const UpdateRoleSchema = z.object({
  role: z.enum(['owner', 'admin', 'member']),
})

// POST /v1/organizations
orgsRouter.post('/', jwtMiddleware, async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = CreateOrgSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const result = await createOrg(c.get('did'), parsed.data.name, parsed.data.role as Role, parsed.data.slug)
  return c.json(result, 201)
})

// GET /v1/organizations/:id
orgsRouter.get('/:id', jwtMiddleware, async c => {
  const org = await getOrg(c.req.param('id')!, c.get('did'))
  return c.json(org)
})

// GET /v1/organizations/:id/members
orgsRouter.get('/:id/members', jwtMiddleware, async c => {
  const members = await getOrgMembers(c.req.param('id')!, c.get('did'))
  return c.json({ members })
})

// POST /v1/organizations/invites/:token/accept
// NOTE: Must be registered BEFORE /:id/invites to avoid Hono matching "invites" as :id
orgsRouter.post('/invites/:token/accept', jwtMiddleware, async c => {
  await acceptInvite(c.req.param('token')!, c.get('did'))
  return c.json({ success: true })
})

// POST /v1/organizations/:id/invites
orgsRouter.post('/:id/invites', jwtMiddleware, async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = InviteSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  const result = await inviteMember(
    c.req.param('id')!,
    c.get('did'),
    parsed.data as { email?: string; did?: string },
    parsed.data.role
  )
  return c.json(result, 201)
})

// PATCH /v1/organizations/:id/members/:userId
orgsRouter.patch('/:id/members/:userId', jwtMiddleware, async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = UpdateRoleSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  }
  await updateMemberRole(c.req.param('id')!, c.req.param('userId')!, parsed.data.role as OrgMemberRole, c.get('did'))
  return c.json({ success: true })
})

// DELETE /v1/organizations/:id/members/:userId
orgsRouter.delete('/:id/members/:userId', jwtMiddleware, async c => {
  await removeMember(c.req.param('id')!, c.req.param('userId')!, c.get('did'))
  return c.json({ success: true })
})

// DELETE /v1/organizations/:id
orgsRouter.delete('/:id', jwtMiddleware, async c => {
  await deleteOrg(c.req.param('id')!, c.get('did'))
  return c.json({ success: true })
})
