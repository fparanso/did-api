// tests/integration/password-reset.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.ADMIN_SECRET = 'test-admin-secret'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

let app: { fetch: (req: Request) => Promise<Response> }
let sql: any

beforeAll(async () => {
  const db = await import('../../src/shared/db')
  sql = db.sql
  await db.runMigrations()
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  app = (await import('../../src/index')).default

  await sql`DELETE FROM org_members`
  await sql`DELETE FROM org_invites`
  await sql`DELETE FROM organizations`
  await sql`DELETE FROM password_reset_tokens`
  await sql`DELETE FROM users WHERE email = 'resetuser@example.com'`
  await sql`DELETE FROM sessions`

  // Create a user for reset tests
  await app.fetch(new Request('http://localhost/v1/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'resetuser@example.com', password: 'oldPassword1', name: 'Reset User' }),
  }))
})

afterAll(async () => {
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(false)
})

const BASE = 'http://localhost'

async function post(path: string, body: unknown) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }))
}

describe('POST /v1/auth/forgot-password', () => {
  test('returns 200 with resetToken when email exists', async () => {
    const res = await post('/v1/auth/forgot-password', { email: 'resetuser@example.com' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.message).toBe('string')
    expect(typeof body.resetToken).toBe('string')
    expect(body.resetToken.length).toBe(64)  // 32 bytes hex = 64 chars
  })

  test('returns 200 with same message shape when email does NOT exist', async () => {
    const res = await post('/v1/auth/forgot-password', { email: 'nobody@example.com' })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.message).toBe('string')
    // No resetToken field — email not found
    expect(body.resetToken).toBeUndefined()
  })
})

describe('POST /v1/auth/reset-password', () => {
  test('full reset flow: get token → reset → login with new password', async () => {
    // Step 1: Get reset token
    const forgotRes = await post('/v1/auth/forgot-password', { email: 'resetuser@example.com' })
    const { resetToken } = await forgotRes.json()

    // Step 2: Reset password
    const resetRes = await post('/v1/auth/reset-password', {
      token: resetToken,
      newPassword: 'newPassword1',
    })
    expect(resetRes.status).toBe(200)
    const resetBody = await resetRes.json()
    expect(typeof resetBody.message).toBe('string')

    // Step 3: Old password no longer works
    const oldLoginRes = await post('/v1/auth/login', {
      email: 'resetuser@example.com',
      password: 'oldPassword1',
    })
    expect(oldLoginRes.status).toBe(401)

    // Step 4: New password works
    const newLoginRes = await post('/v1/auth/login', {
      email: 'resetuser@example.com',
      password: 'newPassword1',
    })
    expect(newLoginRes.status).toBe(200)
  })

  test('sessions are invalidated after reset', async () => {
    // Get token before reset
    const loginBefore = await post('/v1/auth/login', {
      email: 'resetuser@example.com',
      password: 'newPassword1',
    })
    const { token: oldToken } = await loginBefore.json()

    // Reset password
    const forgotRes = await post('/v1/auth/forgot-password', { email: 'resetuser@example.com' })
    const { resetToken } = await forgotRes.json()
    await post('/v1/auth/reset-password', { token: resetToken, newPassword: 'anotherPassword1' })

    // Verify sessions table is cleared for this DID:
    const [userRow] = await sql`SELECT did FROM users WHERE email = 'resetuser@example.com'`
    const sessions = await sql`SELECT id FROM sessions WHERE did = ${userRow.did}`
    expect(sessions.length).toBe(0)
  })

  test('returns 404 for invalid token', async () => {
    const res = await post('/v1/auth/reset-password', {
      token: 'nonexistenttoken'.padEnd(64, 'x'),
      newPassword: 'newPassword1',
    })
    expect(res.status).toBe(404)
    const body = await res.json()
    expect(body.error).toBe('RESET_TOKEN_INVALID')
  })

  test('returns 410 for already used token', async () => {
    const forgotRes = await post('/v1/auth/forgot-password', { email: 'resetuser@example.com' })
    const { resetToken } = await forgotRes.json()

    // Use it once
    await post('/v1/auth/reset-password', { token: resetToken, newPassword: 'usedPass1234' })

    // Try to use it again
    const res = await post('/v1/auth/reset-password', {
      token: resetToken,
      newPassword: 'anotherPass1234',
    })
    expect(res.status).toBe(410)
    const body = await res.json()
    expect(body.error).toBe('RESET_TOKEN_USED')
  })

  test('returns 400 if new password < 8 chars', async () => {
    const forgotRes = await post('/v1/auth/forgot-password', { email: 'resetuser@example.com' })
    const { resetToken } = await forgotRes.json()
    const res = await post('/v1/auth/reset-password', {
      token: resetToken,
      newPassword: 'short',
    })
    expect(res.status).toBe(400)
  })
})
