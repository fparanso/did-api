// tests/integration/oidc4vp.test.ts
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.NODE_ENV = 'test'
process.env.ISSUER_HOST = 'http://localhost'

import { describe, test, expect, beforeAll } from 'bun:test'
import { generateKeyPair, exportJWK } from 'jose'
import { issueSdJwt, discloseSelectiveClaims } from '../../src/shared/crypto/sd-jwt'
import type { JWK } from 'jose'

let app: { fetch: (req: Request) => Promise<Response> }
let verifierToken: string
let holderKp: { privateJwk: JWK; publicJwk: JWK }
let sdJwt: string
let issuerDid: string

beforeAll(async () => {
  const db = await import('../../src/shared/db')
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  await db.runMigrations()
  app = (await import('../../src/index')).default

  const sql = db.sql
  await sql`DELETE FROM vp_sessions`.catch(() => {})

  // Create a verifier account via the DID+auth flow
  const createRes = await app.fetch(new Request('http://localhost/v1/dids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role: 'verifier' }),
  }))
  if (createRes.status !== 201) throw new Error(`DID create failed: ${createRes.status} ${await createRes.text()}`)
  const createBody = await createRes.json()
  const did = createBody.did
  const privateKeyJwk = createBody.privateKey
  issuerDid = did

  // Get challenge and authenticate
  const chalRes = await app.fetch(new Request('http://localhost/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  }))
  const { challengeId, nonce: chalNonce } = await chalRes.json()

  const privateKey = await (async () => {
    const { importJWK } = await import('jose')
    return importJWK(privateKeyJwk, 'ES256') as Promise<CryptoKey>
  })()
  const message = new TextEncoder().encode(`${did}:${chalNonce}`)
  const sigDer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
  const signature = Buffer.from(sigDer).toString('base64')

  const verifyRes = await app.fetch(new Request('http://localhost/v1/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature }),
  }))
  const { token } = await verifyRes.json()
  verifierToken = token

  // Generate holder key pair and a test SD-JWT
  const kp = await generateKeyPair('ES256', { extractable: true })
  holderKp = { privateJwk: await exportJWK(kp.privateKey), publicJwk: await exportJWK(kp.publicKey) }
  const issuerKp = await generateKeyPair('ES256', { extractable: true })
  sdJwt = await issueSdJwt({
    issuerPrivateJwk: await exportJWK(issuerKp.privateKey),
    issuerDid: did,
    subjectDid: 'did:key:zHolder',
    credentialId: 'urn:uuid:test-cred-001',
    vct: 'UniversityDegree',
    claims: { name: 'Alice', degree: 'BSc' },
    holderPublicJwk: holderKp.publicJwk,
  })
})

describe('OID4VP — VP session + direct_post', () => {
  let sessionId: string
  let nonce: string

  test('POST /oauth/vp/initiate creates session', async () => {
    const res = await app.fetch(new Request('http://localhost/oauth/vp/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${verifierToken}` },
      body: JSON.stringify({
        dcql_query: {
          credentials: [{ id: 'cred1', format: 'dc+sd-jwt', meta: { vct_values: ['UniversityDegree'] } }]
        }
      }),
    }))
    expect(res.status).toBe(200)
    const body = await res.json()
    sessionId = body.session_id
    nonce = body.nonce
    expect(sessionId).toBeDefined()
    expect(nonce).toBeDefined()
  })

  test('GET /oauth/request/:id fetches signed JAR request object anonymously', async () => {
    const res = await app.fetch(new Request(`http://localhost/oauth/request/${sessionId}`))
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('application/oauth-authz-req+jwt')
    const jwt = await res.text()
    expect(jwt).toBeTruthy()
    expect(jwt.split('.').length).toBe(3)
  })

  test('POST /oauth/direct_post with valid SD-JWT+KB-JWT returns 200', async () => {
    const audience = 'http://localhost/oauth/direct_post'
    const combined = await discloseSelectiveClaims({
      sdJwt, revealedKeys: ['name'], holderPrivateJwk: holderKp.privateJwk, nonce, audience,
    })
    const form = new FormData()
    form.append('vp_token', combined)
    const res = await app.fetch(new Request('http://localhost/oauth/direct_post', { method: 'POST', body: form }))
    expect(res.status).toBe(200)
  })

  test('GET /oauth/vp-result/:id returns result with valid status', async () => {
    const res = await app.fetch(new Request(`http://localhost/oauth/vp-result/${sessionId}`, {
      headers: { 'Authorization': `Bearer ${verifierToken}` },
    }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(['complete', 'failed', 'pending'].includes(body.status)).toBe(true)
  })
})
