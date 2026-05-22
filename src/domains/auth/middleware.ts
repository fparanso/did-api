// src/domains/auth/middleware.ts
import type { Context, Next } from 'hono'
import { verifyJwt } from './service.js'
import { Errors } from '../../shared/errors.js'
import type { Role } from '../../shared/types.js'

export async function jwtMiddleware(c: Context, next: Next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'UNAUTHORIZED', message: 'Missing Authorization header', status: 401 }, 401)
  }
  try {
    const payload = await verifyJwt(auth.slice(7))
    c.set('did', payload.did)
    c.set('role', payload.role)
    return next()
  } catch {
    return c.json({ error: 'UNAUTHORIZED', message: 'Invalid or expired token', status: 401 }, 401)
  }
}

export function requireRole(...roles: Role[]) {
  return async (c: Context, next: Next) => {
    const role = c.get('role') as Role
    if (!roles.includes(role)) {
      const err = Errors.UNAUTHORIZED_ROLE()
      return c.json({ error: err.code, message: err.message, status: 403 }, 403)
    }
    return next()
  }
}

export function requireOwner(getOwnerId: (c: Context) => Promise<string>) {
  return async (c: Context, next: Next) => {
    const callerDid = c.get('did') as string
    const ownerId = await getOwnerId(c)
    if (callerDid !== ownerId) {
      const err = Errors.FORBIDDEN()
      return c.json({ error: err.code, message: err.message, status: 403 }, 403)
    }
    return next()
  }
}
