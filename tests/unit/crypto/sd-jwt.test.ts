// tests/unit/crypto/sd-jwt.test.ts
import { describe, test, expect } from 'bun:test'
import { generateKeyPair, exportJWK, importJWK, jwtVerify } from 'jose'
import { issueSdJwt, discloseSelectiveClaims, verifySdJwtPresentation } from '../../../src/shared/crypto/sd-jwt'

describe('issueSdJwt', () => {
  test('returns a ~ separated SD-JWT with trailing ~', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer123',
      subjectDid: 'did:key:zSubject456',
      vct: 'UniversityDegree',
      claims: { name: 'Alice', degree: 'BSc', gpa: '3.9' },
      holderPublicJwk,
    })

    // Format: header.payload.sig~disc1~disc2~disc3~
    const parts = sdJwt.split('~')
    expect(parts.length).toBe(5) // jwt + 3 disclosures + trailing empty
    expect(parts[parts.length - 1]).toBe('') // trailing ~
  })

  test('issuer JWT has correct payload fields', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const issuerPublicJwk = await exportJWK(issuerKp.publicKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'UniversityDegree',
      claims: { name: 'Alice' },
      holderPublicJwk,
    })

    const issuerJwt = sdJwt.split('~')[0]
    const issuerPublicKey = await importJWK(issuerPublicJwk, 'ES256')
    const { payload } = await jwtVerify(issuerJwt, issuerPublicKey, { algorithms: ['ES256'] })

    expect(payload.iss).toBe('did:key:zIssuer')
    expect(payload.sub).toBe('did:key:zSubject')
    expect(payload.vct).toBe('UniversityDegree')
    expect((payload as any)._sd).toBeDefined()
    expect(Array.isArray((payload as any)._sd)).toBe(true)
    expect((payload as any)._sd_alg).toBe('sha-256')
    expect((payload as any).cnf).toBeDefined()
    expect((payload as any).cnf.jwk).toBeDefined()
  })

  test('each disclosure is base64url encoded JSON array [salt, key, value]', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { name: 'Bob' },
      holderPublicJwk,
    })

    const parts = sdJwt.split('~')
    const disc = parts[1] // first disclosure
    const decoded = JSON.parse(Buffer.from(disc, 'base64url').toString())
    expect(Array.isArray(decoded)).toBe(true)
    expect(decoded.length).toBe(3) // [salt, key, value]
    expect(decoded[1]).toBe('name')
    expect(decoded[2]).toBe('Bob')
  })

  test('_sd hashes match SHA-256 of disclosures', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { x: '1' },
      holderPublicJwk,
    })

    const parts = sdJwt.split('~')
    const issuerJwt = parts[0]
    const disc = parts[1]

    const payload = JSON.parse(Buffer.from(issuerJwt.split('.')[1], 'base64url').toString())
    const hashBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(disc))
    const expected = Buffer.from(hashBytes).toString('base64url')
    expect(payload._sd).toContain(expected)
  })
})

describe('discloseSelectiveClaims', () => {
  test('returns issuerJwt~selectedDiscs~kb-jwt format', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)
    const holderPrivateJwk = await exportJWK(holderKp.privateKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { name: 'Alice', degree: 'BSc', gpa: '3.9' },
      holderPublicJwk,
    })

    const combined = await discloseSelectiveClaims({
      sdJwt,
      revealedKeys: ['name'],
      holderPrivateJwk,
      nonce: 'test-nonce-123',
      audience: 'https://verifier.example',
    })

    const parts = combined.split('~')
    // issuerJwt + 1 disclosed + kb-jwt = 3 parts (no empty trailing)
    expect(parts.length).toBe(3)
    const kbJwt = parts[parts.length - 1]
    const kbPayload = JSON.parse(Buffer.from(kbJwt.split('.')[1], 'base64url').toString())
    expect(kbPayload.nonce).toBe('test-nonce-123')
    expect(kbPayload.aud).toBe('https://verifier.example')
    expect(kbPayload.sd_hash).toBeDefined()
  })

  test('only selected claims are included in disclosures', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)
    const holderPrivateJwk = await exportJWK(holderKp.privateKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { name: 'Alice', degree: 'BSc', gpa: '3.9' },
      holderPublicJwk,
    })

    const combined = await discloseSelectiveClaims({
      sdJwt,
      revealedKeys: ['name', 'degree'],
      holderPrivateJwk,
      nonce: 'nonce',
      audience: 'aud',
    })

    // parts: [issuerJwt, disc1, disc2, kb-jwt]
    const parts = combined.split('~')
    const disclosures = parts.slice(1, -1) // all but first (issuerJwt) and last (kb-jwt)
    const revealed = disclosures.map(d => {
      const decoded = JSON.parse(Buffer.from(d, 'base64url').toString())
      return decoded[1] // claim name
    })
    expect(revealed).toContain('name')
    expect(revealed).toContain('degree')
    expect(revealed).not.toContain('gpa')
  })
})

describe('verifySdJwtPresentation', () => {
  test('returns valid=true for a correct presentation', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const issuerPublicJwk = await exportJWK(issuerKp.publicKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)
    const holderPrivateJwk = await exportJWK(holderKp.privateKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { name: 'Alice' },
      holderPublicJwk,
    })

    const combined = await discloseSelectiveClaims({
      sdJwt,
      revealedKeys: ['name'],
      holderPrivateJwk,
      nonce: 'verifier-nonce',
      audience: 'https://verifier.example',
    })

    const result = await verifySdJwtPresentation({
      combined,
      issuerPublicJwk,
      expectedNonce: 'verifier-nonce',
      expectedAudience: 'https://verifier.example',
    })

    expect(result.valid).toBe(true)
    expect((result.disclosedClaims as any).name).toBe('Alice')
  })

  test('returns valid=false when nonce is wrong', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const issuerPublicJwk = await exportJWK(issuerKp.publicKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)
    const holderPrivateJwk = await exportJWK(holderKp.privateKey)

    const sdJwt = await issueSdJwt({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zSubject',
      vct: 'Test',
      claims: { name: 'Alice' },
      holderPublicJwk,
    })

    const combined = await discloseSelectiveClaims({
      sdJwt,
      revealedKeys: ['name'],
      holderPrivateJwk,
      nonce: 'correct-nonce',
      audience: 'https://verifier.example',
    })

    const result = await verifySdJwtPresentation({
      combined,
      issuerPublicJwk,
      expectedNonce: 'wrong-nonce',
      expectedAudience: 'https://verifier.example',
    })

    expect(result.valid).toBe(false)
  })
})
