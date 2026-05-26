// tests/unit/crypto/p256.test.ts
import { describe, test, expect } from 'bun:test'
import { generateP256KeyPair, didKeyFromPublicJwk, compressP256Jwk } from '../../../src/shared/crypto/p256'

describe('P-256 key generation', () => {
  test('generateP256KeyPair returns extractable JWKs with crv=P-256', async () => {
    const { privateJwk, publicJwk } = await generateP256KeyPair()
    expect(publicJwk.crv).toBe('P-256')
    expect(publicJwk.kty).toBe('EC')
    expect(publicJwk.x).toBeDefined()
    expect(publicJwk.y).toBeDefined()
    expect(privateJwk.d).toBeDefined()
  })

  test('didKeyFromPublicJwk returns a did:key starting with z', async () => {
    const { publicJwk } = await generateP256KeyPair()
    const did = didKeyFromPublicJwk(publicJwk)
    expect(did).toMatch(/^did:key:z/)
    // P-256 multicodec prefix [0x80, 0x24] encodes to z... prefix in base58btc
    expect(did.length).toBeGreaterThan(50)
  })

  test('compressP256Jwk returns 33 bytes starting with 02 or 03', async () => {
    const { publicJwk } = await generateP256KeyPair()
    const compressed = compressP256Jwk(publicJwk)
    expect(compressed.length).toBe(33)
    expect(compressed[0] === 0x02 || compressed[0] === 0x03).toBe(true)
  })

  test('two key pairs produce different DIDs', async () => {
    const kp1 = await generateP256KeyPair()
    const kp2 = await generateP256KeyPair()
    expect(didKeyFromPublicJwk(kp1.publicJwk)).not.toBe(didKeyFromPublicJwk(kp2.publicJwk))
  })
})
