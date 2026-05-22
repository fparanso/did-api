// tests/integration/email-auth.test.ts
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
  await sql`DELETE FROM users`
  await sql`DELETE FROM presentations`
  await sql`DELETE FROM credentials`
  await sql`DELETE FROM trust_attestations`
  await sql`DELETE FROM auth_challenges`
  await sql`DELETE FROM sessions`
  await sql`TRUNCATE audit_log`
  await sql`DELETE FROM dids`
})

afterAll(async () => {
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(false)
})

const BASE = 'http://localhost'

async function post(path: string, body: unknown, token?: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  }))
}

async function get(path: string, token?: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }))
}

async function patch(path: string, body: unknown, token: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  }))
}

describe('POST /v1/auth/signup', () => {
  test('creates account + DID + returns JWT on valid input', async () => {
    const res = await post('/v1/auth/signup', {
      email: 'alice@example.com',
      password: 'password123',
      name: 'Alice Smith',
      organizationName: 'Acme University',
    })
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(typeof body.token).toBe('string')
    expect(body.user.email).toBe('alice@example.com')
    expect(body.user.name).toBe('Alice Smith')
    expect(body.user.role).toBe('subject')
    expect(body.user.did).toMatch(/^did:key:/)
    // privateKey must NOT be in response
    expect(body.user.privateKey).toBeUndefined()
  })

  test('returns 409 EMAIL_TAKEN on duplicate email', async () => {
    const res = await post('/v1/auth/signup', {
      email: 'alice@example.com',
      password: 'password123',
      name: 'Alice Again',
    })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toBe('EMAIL_TAKEN')
  })

  test('returns 400 on invalid email', async () => {
    const res = await post('/v1/auth/signup', {
      email: 'not-an-email',
      password: 'password123',
      name: 'Bob',
    })
    expect(res.status).toBe(400)
  })

  test('returns 400 on password shorter than 8 chars', async () => {
    const res = await post('/v1/auth/signup', {
      email: 'bob@example.com',
      password: 'short',
      name: 'Bob',
    })
    expect(res.status).toBe(400)
  })
})

describe('POST /v1/auth/login', () => {
  test('returns JWT on valid credentials', async () => {
    const res = await post('/v1/auth/login', {
      email: 'alice@example.com',
      password: 'password123',
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.token).toBe('string')
    expect(body.user.email).toBe('alice@example.com')
  })

  test('returns 401 INVALID_CREDENTIALS for wrong password', async () => {
    const res = await post('/v1/auth/login', {
      email: 'alice@example.com',
      password: 'wrongpassword',
    })
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('INVALID_CREDENTIALS')
  })

  test('returns 401 INVALID_CREDENTIALS for unknown email', async () => {
    const res = await post('/v1/auth/login', {
      email: 'nobody@example.com',
      password: 'password123',
    })
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('INVALID_CREDENTIALS')
  })
})

describe('GET /v1/users/me', () => {
  test('returns profile with organizations list', async () => {
    const loginRes = await post('/v1/auth/login', {
      email: 'alice@example.com',
      password: 'password123',
    })
    const { token } = await loginRes.json()

    const res = await get('/v1/users/me', token)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.email).toBe('alice@example.com')
    expect(body.name).toBe('Alice Smith')
    expect(body.organizationName).toBe('Acme University')
    expect(Array.isArray(body.organizations)).toBe(true)
  })

  test('returns 401 without token', async () => {
    const res = await get('/v1/users/me')
    expect(res.status).toBe(401)
  })
})

describe('PATCH /v1/users/me', () => {
  test('updates name and organizationName', async () => {
    const loginRes = await post('/v1/auth/login', {
      email: 'alice@example.com',
      password: 'password123',
    })
    const { token } = await loginRes.json()

    const res = await patch('/v1/users/me', { name: 'Alice J. Smith' }, token)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.name).toBe('Alice J. Smith')
    expect(body.email).toBe('alice@example.com')  // email unchanged
  })
})

describe('email/password JWT works on protected endpoints', () => {
  test('JWT from login can access /v1/dids/me', async () => {
    const loginRes = await post('/v1/auth/login', {
      email: 'alice@example.com',
      password: 'password123',
    })
    const { token } = await loginRes.json()

    const res = await get('/v1/dids/me', token)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.did).toMatch(/^did:key:/)
  })
})
