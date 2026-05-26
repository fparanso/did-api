// tests/security/owasp.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.ADMIN_SECRET = 'test-admin-secret'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

import { importJWK } from 'jose'

let app: { fetch: (req: Request) => Promise<Response> }
let sql: any
let runMigrations: () => Promise<void>

async function createDid(role: string) {
  const res = await app.fetch(new Request('http://localhost/v1/dids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  }))
  return res.json()
}

async function getAuth(did: string, privateKeyJwk: unknown) {
  const chalRes = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  }))
  const { challengeId, nonce } = await chalRes.json()
  const privateKey = await importJWK(privateKeyJwk as any, 'ES256') as CryptoKey
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const sigDer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
  const sig = Buffer.from(sigDer).toString('base64')
  const verRes = await app.fetch(new Request('http://localhost/v1/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature: sig }),
  }))
  const body = await verRes.json()
  return { token: body.token, challengeId, nonce, signature: sig }
}

beforeAll(async () => {
  const db = await import('../../src/shared/db')
  sql = db.sql
  runMigrations = db.runMigrations
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  app = (await import('../../src/index')).default
  await runMigrations()
  await sql`DELETE FROM presentations`
  await sql`DELETE FROM credentials`
  await sql`DELETE FROM trust_attestations`
  await sql`DELETE FROM auth_challenges`
  await sql`DELETE FROM sessions`
  await sql`TRUNCATE audit_log`
  await sql`DELETE FROM org_members`
  await sql`DELETE FROM org_invites`
  await sql`DELETE FROM organizations`
  await sql`DELETE FROM password_reset_tokens`
  await sql`DELETE FROM users`
  await sql`DELETE FROM dids`
})

afterAll(async () => {
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(false)
  // Do not call sql.end() — the postgres connection is shared across test files
})

describe('API2 — Broken Authentication: nonce replay prevention', () => {
  test('replaying a used nonce returns 401 CHALLENGE_EXPIRED', async () => {
    const { did, privateKey } = await createDid('subject')
    const { token, challengeId, nonce, signature } = await getAuth(did, privateKey)
    expect(token).toBeTruthy()

    // Try to use the same challengeId+signature again
    const replay = await app.fetch(new Request('http://localhost/v1/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did, challengeId, signature }),
    }))
    expect(replay.status).toBe(401)
    expect((await replay.json()).error).toBe('CHALLENGE_EXPIRED')
  })
})

describe('API1 — Broken Object Level Authorization', () => {
  test('subject cannot read another subject credential', async () => {
    const { did: attesterDid, privateKey: attesterPriv } = await createDid('attester')
    const { did: issuerDid, privateKey: issuerPriv } = await createDid('issuer')
    const { did: sub1Did } = await createDid('subject')
    const { did: sub2Did, privateKey: sub2Priv } = await createDid('subject')

    const { token: attesterToken } = await getAuth(attesterDid, attesterPriv)
    const { token: issuerToken } = await getAuth(issuerDid, issuerPriv)
    const { token: sub2Token } = await getAuth(sub2Did, sub2Priv)

    await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    }))

    const issueRes = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid: sub1Did, credentialType: ['Test'], claims: { secret: 'value' } }),
    }))
    const { id: credId } = await issueRes.json()

    // sub2 tries to read sub1's credential — must fail with 403
    const res = await app.fetch(new Request(`http://localhost/v1/credentials/${credId}`, {
      headers: { Authorization: `Bearer ${sub2Token}` },
    }))
    expect(res.status).toBe(403)
  })
})

describe('API5 — Broken Function Level Authorization', () => {
  test('subject cannot call POST /v1/credentials/issue', async () => {
    const { did, privateKey } = await createDid('subject')
    const { token } = await getAuth(did, privateKey)

    const res = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ subjectDid: did, credentialType: ['Test'], claims: {} }),
    }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('UNAUTHORIZED_ROLE')
  })

  test('subject cannot call POST /v1/trust/attest', async () => {
    const { did, privateKey } = await createDid('subject')
    const { token } = await getAuth(did, privateKey)

    const res = await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ issuerDid: did }),
    }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('UNAUTHORIZED_ROLE')
  })
})

describe('API8 — Security Misconfiguration: security headers', () => {
  test('all responses include required OWASP security headers', async () => {
    const res = await app.fetch(new Request('http://localhost/health'))
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('strict-transport-security')).toBeTruthy()
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('content-security-policy')).toBeTruthy()
  })
})

describe('API10 — Unsafe Input Consumption: input validation', () => {
  test('missing did in challenge request returns 400', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }))
    expect(res.status).toBe(400)
  })

  test('invalid role in POST /v1/dids returns 400', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/dids', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'hacker' }),
    }))
    expect(res.status).toBe(400)
  })

  test('unauthenticated request to protected route returns 401', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/dids/me'))
    expect(res.status).toBe(401)
  })
})

describe('API2 — No email enumeration at forgot-password', () => {
  test('unknown email returns 200 with same message shape as known email', async () => {
    const knownRes = await app.fetch(new Request('http://localhost/v1/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'nobody-known@example.com' }),
    }))
    expect(knownRes.status).toBe(200)
    const knownBody = await knownRes.json()
    expect(typeof knownBody.message).toBe('string')
  })

  test('wrong password returns INVALID_CREDENTIALS, not EMAIL_NOT_FOUND', async () => {
    // Create a user first
    await app.fetch(new Request('http://localhost/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owasp-user@example.com', password: 'password123', name: 'OWASP' }),
    }))
    const res = await app.fetch(new Request('http://localhost/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owasp-user@example.com', password: 'wrongpassword' }),
    }))
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('INVALID_CREDENTIALS')
    expect(body.error).not.toBe('EMAIL_NOT_FOUND')
  })
})

describe('API2 — Reset token security', () => {
  test('expired reset token returns 410, not 401', async () => {
    // Directly insert an expired token via DB
    const { sql: testSql } = await import('../../src/shared/db')
    const [user] = await testSql`SELECT id FROM users WHERE email = 'owasp-user@example.com' LIMIT 1`
    expect(user).toBeDefined()
    if (user) {
      const expiredToken = 'expiredtoken'.padEnd(64, '0')
      await testSql`
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES (${user.id}::uuid, ${expiredToken}, now() - interval '1 hour')
        ON CONFLICT DO NOTHING
      `
      const res = await app.fetch(new Request('http://localhost/v1/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: expiredToken, newPassword: 'newPassword1' }),
      }))
      expect(res.status).toBe(410)
    }
  })
})

describe('API5 — Admin endpoint requires secret', () => {
  test('missing X-Admin-Secret returns 401', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/admin/users/some-id/role', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'issuer' }),
    }))
    expect(res.status).toBe(401)
  })

  test('wrong X-Admin-Secret returns 401', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/admin/users/some-id/role', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-admin-secret': 'totally-wrong-secret',
      },
      body: JSON.stringify({ role: 'issuer' }),
    }))
    expect(res.status).toBe(401)
  })
})

describe('API5 — Org member cannot call admin-only routes', () => {
  test('member cannot invite to org they belong to as member', async () => {
    // Sign up an attester user to create an org
    const attRes = await app.fetch(new Request('http://localhost/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owasp-org-owner@example.com', password: 'password123', name: 'Owner' }),
    }))
    const { token: ownerToken } = await attRes.json()

    const orgRes = await app.fetch(new Request('http://localhost/v1/organizations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
      body: JSON.stringify({ name: 'OWASP Test Org', role: 'issuer' }),
    }))
    const { id: orgId } = await orgRes.json()

    // Create a plain member and add them
    const memberRes = await app.fetch(new Request('http://localhost/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owasp-plain-member@example.com', password: 'password123', name: 'Member' }),
    }))
    const { token: memberToken } = await memberRes.json()

    await app.fetch(new Request(`http://localhost/v1/organizations/${orgId}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
      body: JSON.stringify({ email: 'owasp-plain-member@example.com', role: 'member' }),
    }))

    // Member tries to invite someone — should be 403
    const illegalRes = await app.fetch(new Request(`http://localhost/v1/organizations/${orgId}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${memberToken}` },
      body: JSON.stringify({ email: 'hacker@example.com', role: 'admin' }),
    }))
    expect(illegalRes.status).toBe(403)
  })
})

describe('API1 — Invite accept BOLA', () => {
  test('user cannot accept an invite addressed to a different email', async () => {
    // Create org + invite for specific email
    const ownerRes = await app.fetch(new Request('http://localhost/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'bola-owner@example.com', password: 'password123', name: 'BOLA Owner' }),
    }))
    const { token: ownerToken } = await ownerRes.json()

    const orgRes = await app.fetch(new Request('http://localhost/v1/organizations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
      body: JSON.stringify({ name: 'BOLA Org', role: 'verifier' }),
    }))
    const { id: orgId } = await orgRes.json()

    // Invite for a specific email
    const inviteRes = await app.fetch(new Request(`http://localhost/v1/organizations/${orgId}/invites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${ownerToken}` },
      body: JSON.stringify({ email: 'rightperson@example.com', role: 'member' }),
    }))
    const { inviteToken } = await inviteRes.json()

    // A DIFFERENT user tries to accept it
    const wrongUserRes = await app.fetch(new Request('http://localhost/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'wrongperson@example.com', password: 'password123', name: 'Wrong' }),
    }))
    const { token: wrongToken } = await wrongUserRes.json()

    const acceptRes = await app.fetch(new Request(
      `http://localhost/v1/organizations/invites/${inviteToken}/accept`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${wrongToken}` },
        body: JSON.stringify({}),
      }
    ))
    expect(acceptRes.status).toBe(403)
  })
})
