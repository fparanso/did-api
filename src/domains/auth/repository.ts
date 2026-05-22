// src/domains/auth/repository.ts
import { sql } from '../../shared/db.js'

export async function createChallenge(did: string, nonce: string): Promise<string> {
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 min
  const [row] = await sql`
    INSERT INTO auth_challenges (did, nonce, expires_at)
    VALUES (${did}, ${nonce}, ${expiresAt})
    RETURNING id
  `
  return row.id
}

export async function consumeChallenge(
  challengeId: string,
  did: string
): Promise<string | null> {
  const [row] = await sql`
    UPDATE auth_challenges
    SET used = true
    WHERE id = ${challengeId}::uuid
      AND did = ${did}
      AND used = false
      AND expires_at > now()
    RETURNING nonce
  `
  return row?.nonce ?? null
}

export async function createSession(did: string, role: string, token: string): Promise<void> {
  const durationMs = (process.env.NODE_ENV === 'development' ? 120 : 15) * 60 * 1000
  const expiresAt = new Date(Date.now() + durationMs)
  await sql`
    INSERT INTO sessions (did, role, token, expires_at)
    VALUES (${did}, ${role}, ${token}, ${expiresAt})
  `
}
