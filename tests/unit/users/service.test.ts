// tests/unit/users/service.test.ts
import { describe, test, expect } from 'bun:test'

describe('users/service module shape', () => {
  test('exports expected functions', async () => {
    const mod = await import('../../../src/domains/users/service')
    expect(typeof mod.createUser).toBe('function')
    expect(typeof mod.loginUser).toBe('function')
    expect(typeof mod.requestPasswordReset).toBe('function')
    expect(typeof mod.resetPassword).toBe('function')
    expect(typeof mod.getProfile).toBe('function')
    expect(typeof mod.updateProfile).toBe('function')
    expect(typeof mod.upgradeRole).toBe('function')
  })
})

describe('password hashing', () => {
  test('Bun.password hashes and verifies argon2id correctly', async () => {
    const password = 'test-password-123'
    const hash = await Bun.password.hash(password, {
      algorithm: 'argon2id',
      memoryCost: 19456,
      timeCost: 2,
    })
    expect(typeof hash).toBe('string')
    expect(hash).not.toBe(password)
    const valid = await Bun.password.verify(password, hash)
    expect(valid).toBe(true)
    const invalid = await Bun.password.verify('wrong-password', hash)
    expect(invalid).toBe(false)
  })
})
