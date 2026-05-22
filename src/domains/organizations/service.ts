// src/domains/organizations/service.ts
import { createDid, deactivate } from '../did/service.js'
import { findUserByDid, findUserByEmail, findUserById } from '../users/repository.js'
import {
  insertOrg,
  findOrgById,
  findOrgBySlug,
  insertMember,
  findMember,
  updateMemberRole as repoUpdateMemberRole,
  removeMember as repoRemoveMember,
  countOwners,
  listMembers,
  insertInvite,
  findInviteByToken,
  acceptInvite as repoAcceptInvite,
  deleteOrg as repoDeleteOrg,
} from './repository.js'
import { writeAuditLog } from '../../shared/db.js'
import { Errors } from '../../shared/errors.js'
import type { OrgMemberRole, Role } from '../../shared/types.js'

export function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')  // strip combining diacritics
    .replace(/[^a-z0-9\s-]/g, '')     // remove non-alphanumeric
    .trim()
    .replace(/\s+/g, '-')             // spaces → hyphens
    .replace(/-+/g, '-')              // collapse multiple hyphens
}

export async function requireOrgRole(
  orgId: string,
  userId: string,
  minRole: OrgMemberRole
): Promise<OrgMemberRole> {
  const member = await findMember(orgId, userId)
  if (!member) throw Errors.INSUFFICIENT_ORG_ROLE()
  const hierarchy: OrgMemberRole[] = ['member', 'admin', 'owner']
  if (hierarchy.indexOf(member.role) < hierarchy.indexOf(minRole)) {
    throw Errors.INSUFFICIENT_ORG_ROLE()
  }
  return member.role
}

export async function createOrg(
  callerDid: string,
  name: string,
  role: Role,
  slug?: string
): Promise<{
  id: string
  name: string
  slug: string
  did: string
  memberRole: OrgMemberRole
}> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()

  const finalSlug = slug ?? generateSlug(name)
  const existing = await findOrgBySlug(finalSlug)
  if (existing) throw Errors.SLUG_TAKEN()

  const { did: orgDid } = await createDid(role)
  const org = await insertOrg({ name, slug: finalSlug, did: orgDid, ownerId: caller.id })
  await insertMember(org.id, caller.id, 'owner')
  await writeAuditLog(callerDid, 'attest', 'success', org.id)

  return { id: org.id, name: org.name, slug: org.slug, did: org.did, memberRole: 'owner' }
}

export async function getOrg(orgId: string, callerDid: string) {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()
  const org = await findOrgById(orgId)
  if (!org) throw Errors.ORG_NOT_FOUND(orgId)
  await requireOrgRole(orgId, caller.id, 'member')
  return org
}

export async function getOrgMembers(orgId: string, callerDid: string) {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()
  const org = await findOrgById(orgId)
  if (!org) throw Errors.ORG_NOT_FOUND(orgId)
  await requireOrgRole(orgId, caller.id, 'member')
  return listMembers(orgId)
}

export async function inviteMember(
  orgId: string,
  callerDid: string,
  target: { email?: string; did?: string },
  role: 'admin' | 'member'
): Promise<{ inviteToken?: string; expiresAt?: Date; userId?: string; memberRole?: OrgMemberRole }> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()
  await requireOrgRole(orgId, caller.id, 'admin')

  // Resolve target user
  let targetUser = target.did
    ? await findUserByDid(target.did)
    : target.email
    ? await findUserByEmail(target.email)
    : null

  if (target.did && !targetUser) throw Errors.USER_NOT_FOUND()

  // If existing user — add directly
  if (targetUser) {
    const existing = await findMember(orgId, targetUser.id)
    if (existing) throw Errors.ALREADY_MEMBER()
    await insertMember(orgId, targetUser.id, role)
    return { userId: targetUser.id, memberRole: role }
  }

  // Unknown email — create pending invite
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')
  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000)  // 72 hours
  await insertInvite({
    orgId,
    invitedBy: caller.id,
    email: target.email ?? null,
    did: target.did ?? null,
    role,
    token,
    expiresAt,
  })
  return { inviteToken: token, expiresAt }
}

export async function acceptInvite(token: string, callerDid: string): Promise<void> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()

  const invite = await findInviteByToken(token)
  if (!invite) throw Errors.INVITE_NOT_FOUND()
  if (invite.accepted) throw Errors.INVITE_ALREADY_USED()
  if (invite.expiresAt < new Date()) throw Errors.INVITE_EXPIRED()
  if (invite.email && invite.email !== caller.email) throw Errors.FORBIDDEN()

  const existing = await findMember(invite.orgId, caller.id)
  if (existing) throw Errors.ALREADY_MEMBER()

  await insertMember(invite.orgId, caller.id, invite.role)
  await repoAcceptInvite(invite.id)
}

export async function updateMemberRole(
  orgId: string,
  targetUserId: string,
  newRole: OrgMemberRole,
  callerDid: string
): Promise<void> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()

  // Members cannot change anyone's role — only admins and owners
  const callerMembership = await requireOrgRole(orgId, caller.id, 'admin')

  // owners can change anyone except themselves; admins can only promote members to admin
  if (callerMembership === 'admin' && newRole === 'owner') throw Errors.INSUFFICIENT_ORG_ROLE()
  if (caller.id === targetUserId) throw Errors.INSUFFICIENT_ORG_ROLE()

  // Prevent demoting the last owner
  if (newRole !== 'owner') {
    const target = await findMember(orgId, targetUserId)
    if (target?.role === 'owner') {
      const ownerCount = await countOwners(orgId)
      if (ownerCount <= 1) throw Errors.CANNOT_REMOVE_LAST_OWNER()
    }
  }

  await repoUpdateMemberRole(orgId, targetUserId, newRole)
}

export async function removeMember(
  orgId: string,
  targetUserId: string,
  callerDid: string
): Promise<void> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()

  // Allow self-removal (leave org)
  if (caller.id !== targetUserId) {
    const callerMembership = await findMember(orgId, caller.id)
    if (!callerMembership) throw Errors.INSUFFICIENT_ORG_ROLE()
    if (callerMembership.role === 'member') throw Errors.INSUFFICIENT_ORG_ROLE()

    const targetMembership = await findMember(orgId, targetUserId)
    if (targetMembership?.role === 'owner' && callerMembership.role !== 'owner') {
      throw Errors.INSUFFICIENT_ORG_ROLE()
    }
  }

  const target = await findMember(orgId, targetUserId)
  if (target?.role === 'owner') {
    const ownerCount = await countOwners(orgId)
    if (ownerCount <= 1) throw Errors.CANNOT_REMOVE_LAST_OWNER()
  }

  await repoRemoveMember(orgId, targetUserId)
}

export async function deleteOrg(orgId: string, callerDid: string): Promise<void> {
  const caller = await findUserByDid(callerDid)
  if (!caller) throw Errors.USER_NOT_FOUND()
  await requireOrgRole(orgId, caller.id, 'owner')

  const org = await findOrgById(orgId)
  if (!org) throw Errors.ORG_NOT_FOUND(orgId)

  // Deactivate the org DID before deleting (cascades members + invites)
  // The org DID is its own "caller" since it owns itself
  await deactivate(org.did, org.did)
  await repoDeleteOrg(orgId)
  await writeAuditLog(callerDid, 'revoke', 'success', orgId)
}
