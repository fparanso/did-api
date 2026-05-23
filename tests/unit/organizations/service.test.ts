// tests/unit/organizations/service.test.ts
import { describe, test, expect } from 'bun:test'

describe('organizations/service module shape', () => {
  test('exports expected functions', async () => {
    const mod = await import('../../../src/domains/organizations/service')
    expect(typeof mod.createOrg).toBe('function')
    expect(typeof mod.getOrg).toBe('function')
    expect(typeof mod.getOrgMembers).toBe('function')
    expect(typeof mod.inviteMember).toBe('function')
    expect(typeof mod.acceptInvite).toBe('function')
    expect(typeof mod.updateMemberRole).toBe('function')
    expect(typeof mod.removeMember).toBe('function')
    expect(typeof mod.deleteOrg).toBe('function')
    expect(typeof mod.requireOrgRole).toBe('function')
  })
})

describe('slug generation', () => {
  test('generateSlug converts name to url-safe slug', async () => {
    const { generateSlug } = await import('../../../src/domains/organizations/service')
    expect(generateSlug('Acme University')).toBe('acme-university')
    expect(generateSlug('Hello World!!')).toBe('hello-world')
    expect(generateSlug('  spaces  ')).toBe('spaces')
    expect(generateSlug('Ünïcödé')).toBe('unicode')
  })
})
