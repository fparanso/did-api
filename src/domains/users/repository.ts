// src/domains/users/repository.ts
import { sql } from '../../shared/db.js'
import type { UserRecord, UserProfile } from '../../shared/types.js'

export async function insertUser(record: {
  email: string
  passwordHash: string
  name: string
  organizationName: string | null
  did: string
}): Promise<UserRecord> {
  const [row] = await sql`
    INSERT INTO users (email, password_hash, name, organization_name, did)
    VALUES (${record.email}, ${record.passwordHash}, ${record.name},
            ${record.organizationName ?? null}, ${record.did})
    RETURNING id, email, password_hash, name, organization_name, did, created_at
  `
  return rowToUser(row)
}

export async function findUserByEmail(email: string): Promise<UserRecord | null> {
  const [row] = await sql`
    SELECT id, email, password_hash, name, organization_name, did, created_at
    FROM users WHERE email = ${email}
  `
  return row ? rowToUser(row) : null
}

export async function findUserById(id: string): Promise<UserRecord | null> {
  const [row] = await sql`
    SELECT id, email, password_hash, name, organization_name, did, created_at
    FROM users WHERE id = ${id}::uuid
  `
  return row ? rowToUser(row) : null
}

export async function findUserByDid(did: string): Promise<UserRecord | null> {
  const [row] = await sql`
    SELECT id, email, password_hash, name, organization_name, did, created_at
    FROM users WHERE did = ${did}
  `
  return row ? rowToUser(row) : null
}

export async function updateUserProfile(
  id: string,
  updates: { name?: string; organizationName?: string }
): Promise<void> {
  await sql`
    UPDATE users
    SET
      name              = COALESCE(${updates.name ?? null}, name),
      organization_name = COALESCE(${updates.organizationName ?? null}, organization_name)
    WHERE id = ${id}::uuid
  `
}

export async function updatePasswordHash(userId: string, passwordHash: string): Promise<void> {
  await sql`
    UPDATE users SET password_hash = ${passwordHash} WHERE id = ${userId}::uuid
  `
}

export async function insertResetToken(
  userId: string,
  token: string,
  expiresAt: Date
): Promise<void> {
  // Invalidate any previous unused tokens for this user first
  await sql`
    UPDATE password_reset_tokens SET used = true
    WHERE user_id = ${userId}::uuid AND used = false
  `
  await sql`
    INSERT INTO password_reset_tokens (user_id, token, expires_at)
    VALUES (${userId}::uuid, ${token}, ${expiresAt})
  `
}

export async function consumeResetToken(token: string): Promise<{
  userId: string
  userDid: string
} | null> {
  const [row] = await sql`
    SELECT prt.id, prt.user_id, prt.used, prt.expires_at, u.did
    FROM password_reset_tokens prt
    JOIN users u ON u.id = prt.user_id
    WHERE prt.token = ${token}
  `
  if (!row) return null
  return { userId: row.userId, userDid: row.did }
}

export async function findResetToken(token: string): Promise<{
  id: string
  userId: string
  userDid: string
  used: boolean
  expiresAt: Date
} | null> {
  const [row] = await sql`
    SELECT prt.id, prt.user_id, prt.used, prt.expires_at, u.did
    FROM password_reset_tokens prt
    JOIN users u ON u.id = prt.user_id
    WHERE prt.token = ${token}
  `
  if (!row) return null
  return {
    id: row.id,
    userId: row.userId,
    userDid: row.did,
    used: row.used,
    expiresAt: row.expiresAt,
  }
}

export async function markResetTokenUsed(id: string): Promise<void> {
  await sql`UPDATE password_reset_tokens SET used = true WHERE id = ${id}::uuid`
}

export async function invalidateUserSessions(did: string): Promise<void> {
  await sql`DELETE FROM sessions WHERE did = ${did}`
}

export async function getUserProfile(did: string): Promise<UserProfile | null> {
  const [user] = await sql`
    SELECT u.id, u.email, u.name, u.organization_name, u.did, u.created_at, d.role
    FROM users u
    JOIN dids d ON d.id = u.did
    WHERE u.did = ${did}
  `
  if (!user) return null

  const memberships = await sql`
    SELECT o.id, o.name, o.slug, om.role AS member_role
    FROM org_members om
    JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = ${user.id}::uuid
    ORDER BY om.joined_at ASC
  `

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    organizationName: user.organizationName ?? null,
    did: user.did,
    role: user.role,
    createdAt: user.createdAt,
    organizations: memberships.map((m: any) => ({
      id: m.id,
      name: m.name,
      slug: m.slug,
      memberRole: m.memberRole,
    })),
  }
}

function rowToUser(row: any): UserRecord {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.passwordHash,
    name: row.name,
    organizationName: row.organizationName ?? null,
    did: row.did,
    createdAt: row.createdAt,
  }
}
