// tests/unit/organizations/repository.test.ts
import { describe, test, expect } from 'bun:test'

describe('organizations/repository module shape', () => {
  test('exports expected functions', async () => {
    const mod = await import('../../../src/domains/organizations/repository')
    expect(typeof mod.insertOrg).toBe('function')
    expect(typeof mod.findOrgById).toBe('function')
    expect(typeof mod.findOrgBySlug).toBe('function')
    expect(typeof mod.insertMember).toBe('function')
    expect(typeof mod.findMember).toBe('function')
    expect(typeof mod.updateMemberRole).toBe('function')
    expect(typeof mod.removeMember).toBe('function')
    expect(typeof mod.countOwners).toBe('function')
    expect(typeof mod.listMembers).toBe('function')
    expect(typeof mod.insertInvite).toBe('function')
    expect(typeof mod.findInviteByToken).toBe('function')
    expect(typeof mod.acceptInvite).toBe('function')
    expect(typeof mod.deleteOrg).toBe('function')
  })
})
