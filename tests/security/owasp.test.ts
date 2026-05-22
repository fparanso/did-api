// tests/security/owasp.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'

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

async function getAuth(did: string, privateKeyMultibase: string) {
  const publicKeyMultibase = did.replace('did:key:', '')
  const chalRes = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  }))
  const { challengeId, nonce } = await chalRes.json()
  const kp = await Ed25519VerificationKey2020.from({
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase,
    privateKeyMultibase,
  })
  const sig = Buffer.from(await kp.signer().sign({ data: new TextEncoder().encode(`${did}:${nonce}`) })).toString('base64')
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
    const { did, privateKey: privateKeyMultibase } = await createDid('subject')
    const { token, challengeId, nonce, signature } = await getAuth(did, privateKeyMultibase)
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
    const { did: sub1Did, privateKey: sub1Priv } = await createDid('subject')
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
