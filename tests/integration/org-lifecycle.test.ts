// tests/integration/org-lifecycle.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.ADMIN_SECRET = 'test-admin-secret'
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

async function get(path: string, token: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  }))
}

async function patch(path: string, body: unknown, token: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  }))
}

async function del(path: string, token: string) {
  return app.fetch(new Request(`${BASE}${path}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  }))
}

async function signup(email: string, name: string) {
  const res = await post('/v1/auth/signup', { email, password: 'password123', name })
  const body = await res.json()
  return { token: body.token, userId: body.user.id, did: body.user.did }
}

describe('Organization lifecycle', () => {
  let ownerToken: string
  let ownerUserId: string
  let memberToken: string
  let memberUserId: string
  let orgId: string

  test('owner creates an org — gets issuer DID', async () => {
    const owner = await signup('owner@org.test', 'Org Owner')
    ownerToken = owner.token
    ownerUserId = owner.userId

    const res = await post('/v1/organizations', {
      name: 'Test University',
      role: 'issuer',
    }, ownerToken)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.name).toBe('Test University')
    expect(body.slug).toBe('test-university')
    expect(body.did).toMatch(/^did:key:/)
    expect(body.memberRole).toBe('owner')
    orgId = body.id
  })

  test('owner can view org details', async () => {
    const res = await get(`/v1/organizations/${orgId}`, ownerToken)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.name).toBe('Test University')
  })

  test('owner can list org members', async () => {
    const res = await get(`/v1/organizations/${orgId}/members`, ownerToken)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.members.length).toBe(1)
    expect(body.members[0].role).toBe('owner')
  })

  test('owner invites existing user by email — adds directly', async () => {
    const member = await signup('member@org.test', 'Org Member')
    memberToken = member.token
    memberUserId = member.userId

    const res = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'member@org.test',
      role: 'member',
    }, ownerToken)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.userId).toBeDefined()
    expect(body.memberRole).toBe('member')
  })

  test('member can view org after being added', async () => {
    const res = await get(`/v1/organizations/${orgId}`, memberToken)
    expect(res.status).toBe(200)
  })

  test('inviting already-a-member returns 409', async () => {
    const res = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'member@org.test',
      role: 'member',
    }, ownerToken)
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toBe('ALREADY_MEMBER')
  })

  test('owner promotes member to admin', async () => {
    const res = await patch(
      `/v1/organizations/${orgId}/members/${memberUserId}`,
      { role: 'admin' },
      ownerToken
    )
    expect(res.status).toBe(200)

    // Verify role actually changed in DB
    const membersRes = await get(`/v1/organizations/${orgId}/members`, ownerToken)
    const { members } = await membersRes.json()
    const promoted = members.find((m: any) => m.userId === memberUserId)
    expect(promoted?.role).toBe('admin')
  })

  test('member cannot call admin-only invite endpoint', async () => {
    // Re-signup a plain member
    const plain = await signup('plain@org.test', 'Plain Member')
    const inviteRes = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'plain@org.test',
      role: 'member',
    }, ownerToken)
    expect(inviteRes.status).toBe(201)

    // plain member tries to invite someone else
    const noPermRes = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'another@org.test',
      role: 'member',
    }, plain.token)
    expect(noPermRes.status).toBe(403)
  })

  test('invite unknown email → returns inviteToken', async () => {
    const res = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'newperson@org.test',
      role: 'member',
    }, ownerToken)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(typeof body.inviteToken).toBe('string')
    expect(body.inviteToken.length).toBe(64)
  })

  test('new user signs up and accepts invite', async () => {
    // Get invite token
    const inviteRes = await post(`/v1/organizations/${orgId}/invites`, {
      email: 'invitee@org.test',
      role: 'member',
    }, ownerToken)
    const { inviteToken } = await inviteRes.json()

    // Invitee signs up
    const signupRes = await post('/v1/auth/signup', {
      email: 'invitee@org.test',
      password: 'password123',
      name: 'Invitee',
    })
    const { token: inviteeToken } = await signupRes.json()

    // Accept invite
    const acceptRes = await post(`/v1/organizations/invites/${inviteToken}/accept`, {}, inviteeToken)
    expect(acceptRes.status).toBe(200)

    // Verify membership
    const membersRes = await get(`/v1/organizations/${orgId}/members`, ownerToken)
    const { members } = await membersRes.json()
    expect(members.some((m: any) => m.email === 'invitee@org.test')).toBe(true)
  })

  test('cannot remove last owner', async () => {
    const res = await del(
      `/v1/organizations/${orgId}/members/${ownerUserId}`,
      ownerToken
    )
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toBe('CANNOT_REMOVE_LAST_OWNER')
  })

  test('owner deletes org — org and all members removed', async () => {
    const res = await del(`/v1/organizations/${orgId}`, ownerToken)
    expect(res.status).toBe(200)

    // Org should be gone
    const getRes = await get(`/v1/organizations/${orgId}`, ownerToken)
    expect(getRes.status).toBe(404)
  })
})
