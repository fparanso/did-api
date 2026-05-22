// src/domains/auth/service.ts
import { SignJWT, jwtVerify } from 'jose'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { createChallenge, consumeChallenge, createSession } from './repository.js'
import { sql, writeAuditLog } from '../../shared/db.js'
import { Errors } from '../../shared/errors.js'
import type { Role } from '../../shared/types.js'

export async function requestChallenge(did: string): Promise<{ challengeId: string; nonce: string }> {
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url')
  const challengeId = await createChallenge(did, nonce)
  return { challengeId, nonce }
}

export async function verifyChallenge(
  did: string,
  challengeId: string,
  signatureBase64: string
): Promise<string> {
  // Consume nonce (single-use)
  const nonce = await consumeChallenge(challengeId, did)
  if (!nonce) throw Errors.CHALLENGE_EXPIRED()

  // Look up DID record for public key and role
  const [row] = await sql`
    SELECT public_key, role FROM dids WHERE id = ${did} AND deactivated_at IS NULL
  `
  if (!row) throw Errors.DID_NOT_FOUND(did)

  // Verify Ed25519 signature over "did:nonce"
  const keyPair = await Ed25519VerificationKey2020.from({
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: row.publicKey,
  })
  const verifier = keyPair.verifier()
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const signature = Buffer.from(signatureBase64, 'base64')
  const valid = await verifier.verify({ data: message, signature })

  if (!valid) {
    await writeAuditLog(did, 'auth', 'failure')
    throw Errors.INVALID_PROOF()
  }

  const token = await issueJwt(did, row.role as Role)
  await createSession(did, row.role, token)
  await writeAuditLog(did, 'auth', 'success')
  return token
}

export async function issueJwt(did: string, role: Role): Promise<string> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  const expiration = process.env.NODE_ENV === 'development' ? '120m' : '15m'
  return new SignJWT({ did, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime(expiration)
    .setIssuedAt()
    .sign(secret)
}

export async function verifyJwt(token: string): Promise<{ did: string; role: Role }> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  const { payload } = await jwtVerify(token, secret)
  return { did: payload.did as string, role: payload.role as Role }
}
