// src/domains/organizations/repository.ts
import { sql } from '../../shared/db.js'
import type { OrgRecord, OrgMemberRecord, OrgInviteRecord, OrgMemberRole } from '../../shared/types.js'

export async function insertOrg(record: {
  name: string
  slug: string
  did: string
  ownerId: string
}): Promise<OrgRecord> {
  const [row] = await sql`
    INSERT INTO organizations (name, slug, did, owner_id)
    VALUES (${record.name}, ${record.slug}, ${record.did}, ${record.ownerId}::uuid)
    RETURNING id, name, slug, did, owner_id, created_at
  `
  return rowToOrg(row)
}

export async function findOrgById(id: string): Promise<OrgRecord | null> {
  const [row] = await sql`
    SELECT id, name, slug, did, owner_id, created_at
    FROM organizations WHERE id = ${id}::uuid
  `
  return row ? rowToOrg(row) : null
}

export async function findOrgBySlug(slug: string): Promise<OrgRecord | null> {
  const [row] = await sql`
    SELECT id, name, slug, did, owner_id, created_at
    FROM organizations WHERE slug = ${slug}
  `
  return row ? rowToOrg(row) : null
}

export async function insertMember(
  orgId: string,
  userId: string,
  role: OrgMemberRole
): Promise<OrgMemberRecord> {
  const [row] = await sql`
    INSERT INTO org_members (org_id, user_id, role)
    VALUES (${orgId}::uuid, ${userId}::uuid, ${role})
    RETURNING org_id, user_id, role, joined_at
  `
  return { orgId: row.orgId, userId: row.userId, role: row.role, joinedAt: row.joinedAt }
}

export async function findMember(
  orgId: string,
  userId: string
): Promise<OrgMemberRecord | null> {
  const [row] = await sql`
    SELECT org_id, user_id, role, joined_at
    FROM org_members
    WHERE org_id = ${orgId}::uuid AND user_id = ${userId}::uuid
  `
  return row ? { orgId: row.orgId, userId: row.userId, role: row.role, joinedAt: row.joinedAt } : null
}

export async function updateMemberRole(
  orgId: string,
  userId: string,
  role: OrgMemberRole
): Promise<void> {
  await sql`
    UPDATE org_members SET role = ${role}
    WHERE org_id = ${orgId}::uuid AND user_id = ${userId}::uuid
  `
}

export async function removeMember(orgId: string, userId: string): Promise<void> {
  await sql`
    DELETE FROM org_members
    WHERE org_id = ${orgId}::uuid AND user_id = ${userId}::uuid
  `
}

export async function countOwners(orgId: string): Promise<number> {
  const [row] = await sql`
    SELECT COUNT(*)::int AS count FROM org_members
    WHERE org_id = ${orgId}::uuid AND role = 'owner'
  `
  return row.count
}

export async function listMembers(orgId: string): Promise<Array<{
  userId: string
  role: OrgMemberRole
  joinedAt: Date
  name: string
  email: string
}>> {
  return sql`
    SELECT om.user_id, om.role, om.joined_at, u.name, u.email
    FROM org_members om
    JOIN users u ON u.id = om.user_id
    WHERE om.org_id = ${orgId}::uuid
    ORDER BY om.joined_at ASC
  `
}

export async function insertInvite(record: {
  orgId: string
  invitedBy: string
  email: string | null
  did: string | null
  role: 'admin' | 'member'
  token: string
  expiresAt: Date
}): Promise<OrgInviteRecord> {
  const [row] = await sql`
    INSERT INTO org_invites (org_id, invited_by, email, did, role, token, expires_at)
    VALUES (${record.orgId}::uuid, ${record.invitedBy}::uuid,
            ${record.email}, ${record.did},
            ${record.role}, ${record.token}, ${record.expiresAt})
    RETURNING id, org_id, invited_by, email, did, role, token, accepted, expires_at, created_at
  `
  return rowToInvite(row)
}

export async function findInviteByToken(token: string): Promise<OrgInviteRecord | null> {
  const [row] = await sql`
    SELECT id, org_id, invited_by, email, did, role, token, accepted, expires_at, created_at
    FROM org_invites WHERE token = ${token}
  `
  return row ? rowToInvite(row) : null
}

export async function acceptInvite(id: string): Promise<void> {
  await sql`UPDATE org_invites SET accepted = true WHERE id = ${id}::uuid`
}

export async function deleteOrg(id: string): Promise<void> {
  await sql`DELETE FROM organizations WHERE id = ${id}::uuid`
}

function rowToOrg(row: any): OrgRecord {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    did: row.did,
    ownerId: row.ownerId,
    createdAt: row.createdAt,
  }
}

function rowToInvite(row: any): OrgInviteRecord {
  return {
    id: row.id,
    orgId: row.orgId,
    invitedBy: row.invitedBy,
    email: row.email ?? null,
    did: row.did ?? null,
    role: row.role,
    token: row.token,
    accepted: row.accepted,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
  }
}
