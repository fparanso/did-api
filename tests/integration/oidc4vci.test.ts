// tests/integration/oidc4vci.test.ts
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL ?? 'postgresql://localhost/did_zkp_test'
process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
process.env.JWT_SECRET = 'test-secret'
process.env.NODE_ENV = 'test'
process.env.ISSUER_HOST = 'http://localhost'

import { describe, test, expect, beforeAll } from 'bun:test'
import { generateKeyPair, exportJWK, SignJWT } from 'jose'
import type { JWK } from 'jose'

let app: any

beforeAll(async () => {
  const db = await import('../../src/shared/db')
  const rateLimit = await import('../../src/shared/middleware/rate-limit')
  rateLimit.setRateLimitDisabled(true)
  await db.runMigrations()
  app = (await import('../../src/index')).app

  const sql = db.sql
  await sql`DELETE FROM oauth_par_requests`.catch(() => {})
  await sql`DELETE FROM oauth_auth_codes`.catch(() => {})
  await sql`DELETE FROM oauth_dpop_nonces`.catch(() => {})
})

describe('OID4VCI — issuer metadata', () => {
  test('GET /.well-known/openid-credential-issuer returns metadata', async () => {
    const res = await app.fetch(new Request('http://localhost/.well-known/openid-credential-issuer'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.credential_issuer).toBeDefined()
    expect(body.credential_configurations_supported).toBeDefined()
    expect(body.credential_configurations_supported.UniversityDegree.format).toBe('dc+sd-jwt')
  })
})

describe('OID4VCI — PAR flow', () => {
  test('POST /oauth/par returns request_uri', async () => {
    const res = await app.fetch(new Request('http://localhost/oauth/par', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'test-wallet',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
        redirect_uri: 'http://localhost/callback',
        scope: 'UniversityDegree',
      }),
    }))
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/)
    expect(body.expires_in).toBe(90)
  })

  test('POST /oauth/nonce returns c_nonce', async () => {
    const res = await app.fetch(new Request('http://localhost/oauth/nonce', { method: 'POST' }))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.c_nonce).toBeDefined()
    expect(typeof body.c_nonce).toBe('string')
  })
})
