// tests/unit/crypto/did-key.test.ts
import { describe, test, expect } from 'bun:test'
import { generateDidKey, buildDidDocument } from '../../../src/shared/crypto/did-key'

describe('did:key with P-256', () => {
  test('generateDidKey returns a valid did:key', async () => {
    const result = await generateDidKey()
    expect(result.did).toMatch(/^did:key:z/)
    expect(result.publicKeyJwk.crv).toBe('P-256')
    expect(result.privateKeyJwk.d).toBeDefined()
  })

  test('buildDidDocument includes verificationMethod with publicKeyJwk', async () => {
    const { did, publicKeyJwk } = await generateDidKey()
    const doc = buildDidDocument(did, publicKeyJwk)
    expect(doc.id).toBe(did)
    expect(doc.verificationMethod[0].publicKeyJwk).toEqual(publicKeyJwk)
    expect(doc.verificationMethod[0].type).toBe('Multikey')
  })

  test('two calls produce different DIDs', async () => {
    const r1 = await generateDidKey()
    const r2 = await generateDidKey()
    expect(r1.did).not.toBe(r2.did)
  })
})
