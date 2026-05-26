// src/shared/crypto/sd-jwt.ts
import { SignJWT, importJWK } from 'jose'
import type { JWK } from 'jose'

export interface SdJwtIssueOptions {
  issuerPrivateJwk: JWK
  issuerDid: string
  subjectDid: string
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
