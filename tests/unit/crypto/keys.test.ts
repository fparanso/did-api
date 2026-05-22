// tests/unit/crypto/keys.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { encryptKey, decryptKey } from '../../../src/shared/crypto/keys'

describe('encryptKey / decryptKey', () => {
  beforeAll(() => {
    process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
  })

  test('round-trip preserves the value', async () => {
    const original = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
    const encrypted = await encryptKey(original)
    const decrypted = await decryptKey(encrypted)
    expect(decrypted).toBe(original)
  })

  test('each encryption produces a unique ciphertext', async () => {
    const val = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
    const enc1 = await encryptKey(val)
    const enc2 = await encryptKey(val)
    expect(enc1).not.toBe(enc2)
  })

  test('ciphertext contains iv separator', async () => {
    const encrypted = await encryptKey('test')
    expect(encrypted).toContain(':')
  })
})
