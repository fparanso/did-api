// tests/unit/crypto/did-key.test.ts
import { describe, test, expect } from 'bun:test'
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../../src/shared/crypto/did-key'

describe('generateDidKey', () => {
  test('returns a did:key DID starting with did:key:z6Mk', async () => {
    const result = await generateDidKey()
    expect(result.did).toMatch(/^did:key:z6Mk/)
    expect(result.publicKeyMultibase).toMatch(/^z6Mk/)
    expect(result.privateKeyMultibase).toBeTruthy()
  })

  test('each call produces a unique DID', async () => {
    const a = await generateDidKey()
    const b = await generateDidKey()
    expect(a.did).not.toBe(b.did)
  })
})

describe('generateBlsKeyPair', () => {
  test('returns multibase-encoded BLS12-381 G2 key pair', async () => {
    const result = await generateBlsKeyPair('did:key:z6MkTest')
    expect(result.publicKeyMultibase).toBeTruthy()
    expect(result.secretKeyMultibase).toBeTruthy()
  })

  test('each call produces a unique key pair', async () => {
    const a = await generateBlsKeyPair('did:key:z6MkTest')
    const b = await generateBlsKeyPair('did:key:z6MkTest')
    expect(a.publicKeyMultibase).not.toBe(b.publicKeyMultibase)
  })
})

describe('buildDidDocument', () => {
  test('produces a valid DID document shape', async () => {
    const { did, publicKeyMultibase } = await generateDidKey()
    const doc = buildDidDocument(did, publicKeyMultibase)
    expect((doc['@context'] as string[]).length).toBeGreaterThanOrEqual(2)
    expect(doc.id).toBe(did)
    expect((doc.verificationMethod as unknown[]).length).toBe(1)
    expect((doc.authentication as unknown[]).length).toBe(1)
  })

  test('includes BLS key when provided', async () => {
    const { did, publicKeyMultibase } = await generateDidKey()
    const bls = await generateBlsKeyPair(did)
    const doc = buildDidDocument(did, publicKeyMultibase, bls.publicKeyMultibase)
    expect((doc.verificationMethod as unknown[]).length).toBe(2)
    expect((doc.assertionMethod as unknown[]).length).toBe(2)
  })
})
