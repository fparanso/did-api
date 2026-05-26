// tests/integration/revocation.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

import { importJWK } from 'jose'

let app: { fetch: (req: Request) => Promise<Response> }
let sql: any
let runMigrations: () => Promise<void>

async function createAndAuth(role: string) {
  const createRes = await app.fetch(new Request('http://localhost/v1/dids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  }))
  const createBody = await createRes.json()
  const did: string = createBody.did
  const privateKeyJwk = createBody.privateKey

  const chalRes = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  }))
  const { challengeId, nonce } = await chalRes.json()

  const privateKey = await importJWK(privateKeyJwk, 'ES256') as CryptoKey
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const sigDer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
  const signature = Buffer.from(sigDer).toString('base64')

  const verRes = await app.fetch(new Request('http://localhost/v1/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature }),
  }))
  const { token } = await verRes.json()
  return { did, token }
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

describe('Credential revocation', () => {
  test('status endpoint returns revoked after revocation', async () => {
    const { did: attesterDid, token: attesterToken } = await createAndAuth('attester')
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid } = await createAndAuth('subject')

    await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    }))

    const issueRes = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Bob' } }),
    }))
    expect(issueRes.status).toBe(201)
    const { id: credentialId } = await issueRes.json()

    // Revoke
    const revokeRes = await app.fetch(new Request(`http://localhost/v1/credentials/${credentialId}/revoke`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${issuerToken}` },
    }))
    expect(revokeRes.status).toBe(200)

    // Status shows revoked
    const statusRes = await app.fetch(new Request(`http://localhost/v1/credentials/${credentialId}/status`))
    expect(statusRes.status).toBe(200)
    expect((await statusRes.json()).status).toBe('revoked')
  })

  test('deriving a VP from a revoked credential returns 422', async () => {
    const { did: attesterDid, token: attesterToken } = await createAndAuth('attester')
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid, token: subjectToken } = await createAndAuth('subject')

    await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    }))

    const issueRes = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Carol' } }),
    }))
    const { id: credentialId } = await issueRes.json()

    await app.fetch(new Request(`http://localhost/v1/credentials/${credentialId}/revoke`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${issuerToken}` },
    }))

    const deriveRes = await app.fetch(new Request('http://localhost/v1/presentations/derive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${subjectToken}` },
      body: JSON.stringify({ credentialId, revealedClaims: ['name'] }),
    }))
    expect(deriveRes.status).toBe(422)
    expect((await deriveRes.json()).error).toBe('CREDENTIAL_REVOKED')
  })
})

describe('Trust path enforcement', () => {
  test('issuance fails when issuer has no attestation', async () => {
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid } = await createAndAuth('subject')

    const res = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Dave' } }),
    }))
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('ISSUER_NOT_TRUSTED')
  })

  test('issuance succeeds after attestation is granted', async () => {
    const { did: attesterDid, token: attesterToken } = await createAndAuth('attester')
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid } = await createAndAuth('subject')

    await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    }))

    const res = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Eve' } }),
    }))
    expect(res.status).toBe(201)
  })
})
