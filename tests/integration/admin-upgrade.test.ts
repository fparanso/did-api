// tests/integration/admin-upgrade.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.ADMIN_SECRET = 'super-secret-admin'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

let app: any
let sql: any

beforeAll(async () => {
  const db = await import('../../src/shared/db')
  sql = db.sql
  await db.runMigrations()
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  app = (await import('../../src/index')).app

  await sql`DELETE FROM password_reset_tokens`
  await sql`DELETE FROM users WHERE email = 'upgradeuser@example.com'`
  await sql`DELETE FROM sessions`
})

afterAll(async () => {
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(false)
})

const BASE = 'http://localhost'

async function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }))
}

describe('POST /v1/admin/users/:id/role', () => {
  test('upgrades a subject to issuer with valid admin secret', async () => {
    // Create user
    const signupRes = await post('/v1/auth/signup', {
      email: 'upgradeuser@example.com',
      password: 'password123',
      name: 'Upgrade User',
    })
    const { user } = await signupRes.json()
    expect(user.role).toBe('subject')

    // Upgrade role
    const upgradeRes = await post(
      `/v1/admin/users/${user.id}/role`,
      { role: 'issuer' },
      { 'x-admin-secret': 'super-secret-admin' }
    )
    expect(upgradeRes.status).toBe(200)
    const upgradeBody = await upgradeRes.json()
    expect(upgradeBody.success).toBe(true)

    // Login again — new JWT should have issuer role
    const loginRes = await post('/v1/auth/login', {
      email: 'upgradeuser@example.com',
      password: 'password123',
    })
    const loginBody = await loginRes.json()
    expect(loginBody.user.role).toBe('issuer')
  })

  test('returns 401 with wrong admin secret', async () => {
    const res = await post(
      '/v1/admin/users/some-uuid/role',
      { role: 'issuer' },
      { 'x-admin-secret': 'wrong-secret' }
    )
    expect(res.status).toBe(401)
  })

  test('returns 401 with missing admin secret', async () => {
    const res = await post('/v1/admin/users/some-uuid/role', { role: 'issuer' })
    expect(res.status).toBe(401)
  })

  test('returns 400 for invalid role value', async () => {
    const res = await post(
      '/v1/admin/users/some-uuid/role',
      { role: 'superadmin' },
      { 'x-admin-secret': 'super-secret-admin' }
    )
    expect(res.status).toBe(400)
  })
})
