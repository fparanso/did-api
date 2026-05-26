// tests/integration/lifecycle.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'

// Set env vars BEFORE importing the app
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.NODE_ENV = 'test'
process.env.CORS_ORIGIN = 'http://localhost:3000'

import { importJWK } from 'jose'

let app: { fetch: (req: Request) => Promise<Response> }
let sql: any
let runMigrations: () => Promise<void>

beforeAll(async () => {
  // Dynamic import after env vars are set (db.ts opens a pg connection at import time)
  const db = await import('../../src/shared/db')
  sql = db.sql
  runMigrations = db.runMigrations
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  app = (await import('../../src/index')).default

  await runMigrations()

  // Clean test data — order matters: children before parents
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
  // Do not call sql.end() — the postgres connection is shared across test files
})

// Helper: create a DID and authenticate, returning { did, token, privateKeyMultibase }
async function createAndAuth(role: string) {
  // 1. Create DID
  const createRes = await app.fetch(new Request('http://localhost/v1/dids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  }))
  expect(createRes.status).toBe(201)
  const createBody = await createRes.json()
  const did: string = createBody.did
  const privateKeyJwk = createBody.privateKey // raw P-256 private JWK (returned once at creation)

  // 2. Get challenge
  const chalRes = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  }))
  expect(chalRes.status).toBe(200)
  const { challengeId, nonce } = await chalRes.json()

  // 3. Sign the nonce with P-256 ECDSA
  const privateKey = await importJWK(privateKeyJwk, 'ES256') as CryptoKey
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const sigDer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
  const signature = Buffer.from(sigDer).toString('base64')

  // 4. Verify and get token
  const verifyRes = await app.fetch(new Request('http://localhost/v1/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature }),
  }))
  expect(verifyRes.status).toBe(200)
  const { token } = await verifyRes.json()

  return { did, token }
}

describe('Full DID+VC+VP lifecycle', () => {
  let attesterDid: string, attesterToken: string
  let issuerDid: string, issuerToken: string
  let subjectDid: string, subjectToken: string
  let verifierDid: string, verifierToken: string
  let credentialId: string
  let presentationId: string

  test('1. Register all four actor roles', async () => {
    ;({ did: attesterDid, token: attesterToken } = await createAndAuth('attester'))
    ;({ did: issuerDid, token: issuerToken } = await createAndAuth('issuer'))
    ;({ did: subjectDid, token: subjectToken } = await createAndAuth('subject'))
    ;({ did: verifierDid, token: verifierToken } = await createAndAuth('verifier'))

    expect(attesterDid).toMatch(/^did:key:/)
    expect(issuerDid).toMatch(/^did:key:/)
    expect(subjectDid).toMatch(/^did:key:/)
    expect(verifierDid).toMatch(/^did:key:/)
  })

  test('2. Attester vouches for issuer', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    }))
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.id).toBeTruthy()
  })

  test('3. Trust registry shows issuer as trusted', async () => {
    const res = await app.fetch(new Request(`http://localhost/v1/trust/issuers/${issuerDid}`))
    expect(res.status).toBe(200)
    expect((await res.json()).trusted).toBe(true)
  })

  test('4. Issuer issues a VC to subject', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({
        subjectDid,
        credentialType: ['UniversityDegree'],
        claims: { name: 'Alice', degree: 'BSc Computer Science', gpa: '3.9' },
      }),
    }))
    expect(res.status).toBe(201)
    const body = await res.json()
    credentialId = body.id
    expect(credentialId).toMatch(/^urn:uuid:/)
    expect(body.proof?.type).toBe('DataIntegrityProof')
  })

  test('5. Subject derives a VP revealing only name and degree (not gpa)', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/presentations/derive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${subjectToken}` },
      body: JSON.stringify({
        credentialId,
        revealedClaims: ['name', 'degree'],
      }),
    }))
    expect(res.status).toBe(201)
    const body = await res.json()
    presentationId = body.id
    expect(body.disclosedClaims.name).toBe('Alice')
    expect(body.disclosedClaims.degree).toBeTruthy()
    expect(body.disclosedClaims.gpa).toBeUndefined()
  })

  test('6. Verifier verifies the VP successfully', async () => {
    // Fetch the VP document
    const vpRes = await app.fetch(new Request(`http://localhost/v1/presentations/${presentationId}`, {
      headers: { Authorization: `Bearer ${subjectToken}` },
    }))
    expect(vpRes.status).toBe(200)
    const { document } = await vpRes.json()

    const res = await app.fetch(new Request('http://localhost/v1/presentations/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${verifierToken}` },
      body: JSON.stringify({ presentation: document }),
    }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.valid).toBe(true)
    expect(body.issuerTrusted).toBe(true)
    expect(body.credentialStatus).toBe('active')
  })

  test('7. DID resolution works for all actors', async () => {
    const res = await app.fetch(new Request(`http://localhost/v1/dids/${issuerDid}`))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.document.id).toBe(issuerDid)
  })

  test('8. GET /v1/dids/me returns caller DID', async () => {
    const res = await app.fetch(new Request('http://localhost/v1/dids/me', {
      headers: { Authorization: `Bearer ${subjectToken}` },
    }))
    expect(res.status).toBe(200)
    expect((await res.json()).did).toBe(subjectDid)
  })
})
