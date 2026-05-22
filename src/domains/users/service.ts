// src/domains/users/service.ts
import { createDid } from '../did/service.js'
import { issueJwt } from '../auth/service.js'
import {
  insertUser,
  findUserByEmail,
  findUserById,
  findUserByDid,
  updateUserProfile,
  updatePasswordHash,
  insertResetToken,
  findResetToken,
  markResetTokenUsed,
  invalidateUserSessions,
  getUserProfile,
} from './repository.js'
import { sql, writeAuditLog } from '../../shared/db.js'
import { Errors } from '../../shared/errors.js'
import type { Role, UserProfile } from '../../shared/types.js'

const ARGON2_OPTIONS = { algorithm: 'argon2id' as const, memoryCost: 19456, timeCost: 2 }

export async function createUser(
  email: string,
  password: string,
  name: string,
  organizationName?: string
): Promise<{ token: string; user: Omit<UserProfile, 'organizations'> & { organizations: [] } }> {
  // Check email uniqueness before touching the DID table
  const existing = await findUserByEmail(email)
  if (existing) throw Errors.EMAIL_TAKEN()

  const passwordHash = await Bun.password.hash(password, ARGON2_OPTIONS)

  // Create DID first so the FK constraint is satisfied
  const { did, role } = await createDid('subject')

  const user = await insertUser({
    email,
    passwordHash,
    name,
    organizationName: organizationName ?? null,
    did,
  })

  const token = await issueJwt(did, 'subject')
  await sql`
    INSERT INTO sessions (did, role, token, expires_at)
    VALUES (${did}, 'subject', ${token},
            now() + interval '15 minutes')
  `
  await writeAuditLog(did, 'auth', 'success')

  return {
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      organizationName: user.organizationName,
      did,
      role,
      createdAt: user.createdAt,
      organizations: [],
    },
  }
}

export async function loginUser(
  email: string,
  password: string
): Promise<{ token: string; user: UserProfile }> {
  const user = await findUserByEmail(email)
  // Always run password.verify even if user not found to prevent timing attacks
  const dummyHash = '$argon2id$v=19$m=19456,t=2,p=1$dummy'
  const hashToCheck = user?.passwordHash ?? dummyHash

  const valid = await Bun.password.verify(password, hashToCheck)

  if (!user || !valid) {
    if (user) await writeAuditLog(user.did, 'auth', 'failure')
    throw Errors.INVALID_CREDENTIALS()
  }

  const [didRow] = await sql`SELECT role FROM dids WHERE id = ${user.did}`
  const role = didRow.role as Role

  const token = await issueJwt(user.did, role)
  await sql`
    INSERT INTO sessions (did, role, token, expires_at)
    VALUES (${user.did}, ${role}, ${token},
            now() + interval '15 minutes')
  `
  await writeAuditLog(user.did, 'auth', 'success')

  const profile = await getUserProfile(user.did)
  return { token, user: profile! }
}

export async function requestPasswordReset(
  email: string
): Promise<{ resetToken: string | null }> {
  const user = await findUserByEmail(email)
  if (!user) return { resetToken: null }   // no enumeration — caller always gets 200

  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000)  // 1 hour
  await insertResetToken(user.id, token, expiresAt)
  await writeAuditLog(user.did, 'auth', 'success')

  return { resetToken: token }
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  const record = await findResetToken(token)
  if (!record) throw Errors.RESET_TOKEN_INVALID()
  if (record.used) throw Errors.RESET_TOKEN_USED()
  if (record.expiresAt < new Date()) throw Errors.RESET_TOKEN_EXPIRED()

  const passwordHash = await Bun.password.hash(newPassword, ARGON2_OPTIONS)

  await sql.begin(async tx => {
    await tx`UPDATE users SET password_hash = ${passwordHash} WHERE id = ${record.userId}::uuid`
    await tx`UPDATE password_reset_tokens SET used = true WHERE id = ${record.id}::uuid`
    await tx`DELETE FROM sessions WHERE did = ${record.userDid}`
  })

  await writeAuditLog(record.userDid, 'auth', 'success')
}

export async function getProfile(did: string): Promise<UserProfile> {
  const profile = await getUserProfile(did)
  if (!profile) throw Errors.USER_NOT_FOUND()
  return profile
}

export async function updateProfile(
  did: string,
  updates: { name?: string; organizationName?: string }
): Promise<UserProfile> {
  const user = await findUserByDid(did)
  if (!user) throw Errors.USER_NOT_FOUND()
  await updateUserProfile(user.id, updates)
  const profile = await getUserProfile(did)
  return profile!
}

export async function upgradeRole(userId: string, role: Role): Promise<void> {
  const user = await findUserById(userId)
  if (!user) throw Errors.USER_NOT_FOUND()
  await sql`UPDATE dids SET role = ${role} WHERE id = ${user.did}`
  await writeAuditLog(user.did, 'auth', 'success')
}
