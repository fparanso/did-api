// src/shared/crypto/sd-jwt.ts
import { SignJWT, importJWK, jwtVerify } from 'jose'
import type { JWK } from 'jose'

export interface SdJwtIssueOptions {
  issuerPrivateJwk: JWK
  issuerDid: string
  subjectDid: string
  credentialId?: string  // Optional: defaults to urn:uuid:<randomUUID> if not provided
  vct: string
  claims: Record<string, unknown>
  holderPublicJwk: JWK
}

async function sha256Base64url(input: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Buffer.from(bytes).toString('base64url')
}

function randomSalt(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url')
}

export async function issueSdJwt(opts: SdJwtIssueOptions): Promise<string> {
  const { issuerPrivateJwk, issuerDid, subjectDid, vct, claims, holderPublicJwk } = opts
  const credentialId = opts.credentialId ?? `urn:uuid:${crypto.randomUUID()}`

  // Build disclosures: one per claim
  const disclosures: string[] = []
  const sdHashes: string[] = []

  for (const [key, value] of Object.entries(claims)) {
    const salt = randomSalt()
    const disclosure = Buffer.from(JSON.stringify([salt, key, value])).toString('base64url')
    disclosures.push(disclosure)
    sdHashes.push(await sha256Base64url(disclosure))
  }

  const privateKey = await importJWK(issuerPrivateJwk, 'ES256')

  const issuerJwt = await new SignJWT({
    vct,
    sub: subjectDid,
    jti: credentialId,
    _sd: sdHashes,
    _sd_alg: 'sha-256',
    cnf: { jwk: holderPublicJwk },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt' })
    .setIssuer(issuerDid)
    .setIssuedAt()
    .sign(privateKey)

  // Format: issuerJwt~disc1~disc2~...~ (trailing ~)
  return [issuerJwt, ...disclosures, ''].join('~')
}

export interface DiscloseOptions {
  sdJwt: string
  revealedKeys: string[]
  holderPrivateJwk: JWK
  nonce: string
  audience: string
}

export interface VerifyResult {
  valid: boolean
  disclosedClaims: Record<string, unknown>
  error?: string
}

export interface VerifyOptions {
  combined: string
  issuerPublicJwk: JWK
  expectedNonce: string
  expectedAudience: string
}

export async function discloseSelectiveClaims(opts: DiscloseOptions): Promise<string> {
  const { sdJwt, revealedKeys, holderPrivateJwk, nonce, audience } = opts

  // sdJwt = issuerJwt~disc1~disc2~...~ (trailing ~)
  const parts = sdJwt.split('~')
  const issuerJwt = parts[0]
  const allDisclosures = parts.slice(1, -1) // strip trailing empty string

  // Filter to only revealed disclosures
  const selectedDisclosures = allDisclosures.filter(d => {
    try {
      const decoded = JSON.parse(Buffer.from(d, 'base64url').toString())
      return revealedKeys.includes(decoded[1])
    } catch {
      return false
    }
  })

  // sd_hash = SHA-256 of issuerJwt~disc1~...~ (with trailing ~, without KB-JWT)
  const presentationPrefix = [issuerJwt, ...selectedDisclosures, ''].join('~')
  const sdHash = await sha256Base64url(presentationPrefix)

  // Build KB-JWT
  const holderKey = await importJWK(holderPrivateJwk, 'ES256')
  const kbJwt = await new SignJWT({ nonce, aud: audience, sd_hash: sdHash })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .setIssuedAt()
    .sign(holderKey)

  // Final: issuerJwt~disc1~...~kb-jwt (NO trailing ~)
  return [issuerJwt, ...selectedDisclosures, kbJwt].join('~')
}

export async function verifySdJwtPresentation(opts: VerifyOptions): Promise<VerifyResult> {
  const { combined, issuerPublicJwk, expectedNonce, expectedAudience } = opts

  try {
    const parts = combined.split('~')
    if (parts.length < 2) return { valid: false, disclosedClaims: {}, error: 'Invalid format' }

    const issuerJwt = parts[0]
    const kbJwt = parts[parts.length - 1]
    const disclosures = parts.slice(1, -1)

    // 1. Verify issuer JWT
    const issuerKey = await importJWK(issuerPublicJwk, 'ES256')
    const { payload: issuerPayload } = await jwtVerify(issuerJwt, issuerKey, { algorithms: ['ES256'] })
    const sdHashes = (issuerPayload as any)._sd as string[] ?? []
    const holderJwk: JWK = (issuerPayload as any).cnf?.jwk

    // 2. Verify disclosures match _sd hashes
    for (const disc of disclosures) {
      const hash = await sha256Base64url(disc)
      if (!sdHashes.includes(hash)) {
        return { valid: false, disclosedClaims: {}, error: `Disclosure hash mismatch: ${disc}` }
      }
    }

    // 3. Rebuild sd_hash and verify KB-JWT
    const presentationPrefix = [issuerJwt, ...disclosures, ''].join('~')
    const expectedSdHash = await sha256Base64url(presentationPrefix)
    const holderKey = await importJWK(holderJwk, 'ES256')
    const { payload: kbPayload } = await jwtVerify(kbJwt, holderKey, { typ: 'kb+jwt', algorithms: ['ES256'] })

    if (kbPayload.nonce !== expectedNonce) {
      return { valid: false, disclosedClaims: {}, error: 'Nonce mismatch' }
    }
    if (kbPayload.aud !== expectedAudience) {
      return { valid: false, disclosedClaims: {}, error: 'Audience mismatch' }
    }
    if ((kbPayload as any).sd_hash !== expectedSdHash) {
      return { valid: false, disclosedClaims: {}, error: 'sd_hash mismatch' }
    }

    // 4. Decode disclosed claims
    const disclosedClaims: Record<string, unknown> = {}
    for (const disc of disclosures) {
      const decoded = JSON.parse(Buffer.from(disc, 'base64url').toString())
      disclosedClaims[decoded[1]] = decoded[2]
    }

    return { valid: true, disclosedClaims }
  } catch (err) {
    return { valid: false, disclosedClaims: {}, error: String(err) }
  }
}
