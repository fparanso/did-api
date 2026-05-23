// tests/unit/users/repository.test.ts
import { describe, test, expect } from 'bun:test'

// Lightweight smoke tests — repository functions are thin DB wrappers;
// full behaviour is covered by integration tests.
describe('users/repository module shape', () => {
  test('exports expected functions', async () => {
    const mod = await import('../../../src/domains/users/repository')
    expect(typeof mod.insertUser).toBe('function')
    expect(typeof mod.findUserByEmail).toBe('function')
    expect(typeof mod.findUserById).toBe('function')
    expect(typeof mod.findUserByDid).toBe('function')
    expect(typeof mod.updateUserProfile).toBe('function')
    expect(typeof mod.insertResetToken).toBe('function')
    expect(typeof mod.consumeResetToken).toBe('function')
    expect(typeof mod.invalidateUserSessions).toBe('function')
    expect(typeof mod.updatePasswordHash).toBe('function')
  })
})
