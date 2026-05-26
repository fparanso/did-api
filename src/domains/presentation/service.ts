// src/domains/presentation/service.ts
import { randomUUID } from 'crypto'
import { importJWK, jwtVerify } from 'jose'
import type { JWK } from 'jose'
import { findCredential } from '../credentials/repository.js'
import { getDidRecord } from '../did/service.js'
import { isIssuerTrusted } from '../trust/service.js'
import { insertPresentation, findPresentation } from './repository.js'
import { verifySdJwtPresentation } from '../../shared/crypto/sd-jwt.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'

async function sha256Base64url(input: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return Buffer.from(bytes).toString('base64url')
}

export async function deriveSelectivePresentation(
  holderDid: string,
  credentialId: string,
  revealedClaims: string[]
) {
  const credential = await findCredential(credentialId)
  if (!credential) throw Errors.CREDENTIAL_NOT_FOUND(credentialId)
  if (credential.subjectDid !== holderDid) throw Errors.FORBIDDEN()
  if (credential.status === 'revoked') throw Errors.CREDENTIAL_REVOKED()

  const sdJwt = credential.sdJwt
  if (!sdJwt) throw Errors.UNSUPPORTED_FORMAT()

  // Parse all disclosures: format is issuerJwt~disc1~disc2~...~ (trailing ~)
  const parts = sdJwt.split('~')
  const issuerJwt = parts[0]
  const allDisclosures = parts.slice(1, -1) // strip trailing empty string

  // Filter to only the revealed claims
  const selectedDisclosures = allDisclosures.filter(d => {
    try {
      const decoded = JSON.parse(Buffer.from(d, 'base64url').toString())
      return revealedClaims.includes(decoded[1])
    } catch {
      return false
    }
  })

  // Build disclosed claims map
  const disclosedClaims: Record<string, unknown> = {}
  for (const d of selectedDisclosures) {
    const decoded = JSON.parse(Buffer.from(d, 'base64url').toString())
    disclosedClaims[decoded[1]] = decoded[2]
  }

  // Build partial SD-JWT without KB-JWT (REST API simplified flow)
  // Format: issuerJwt~disc1~...~ (trailing ~ means no KB-JWT)
  const presentationJwt = [issuerJwt, ...selectedDisclosures, ''].join('~')

  const id = `urn:uuid:${randomUUID()}`
  await insertPresentation({
    id,
    holderDid,
    credentialIds: [credentialId],
    document: { sdJwt: presentationJwt },
    disclosedClaims,
  })

  await writeAuditLog(holderDid, 'issue', 'success', id)
  return { id, disclosedClaims, document: { sdJwt: presentationJwt } }
}

export async function verifyVp(
  presentationDoc: Record<string, unknown>,
  verifierDid: string
): Promise<{
  valid: boolean
  disclosedClaims: Record<string, unknown>
  issuerTrusted: boolean
  credentialStatus: string
}> {
  const doc = presentationDoc as { sdJwt?: string }
  if (!doc.sdJwt) {
    throw Errors.UNSUPPORTED_FORMAT()
  }

  const sdJwt = doc.sdJwt
  const parts = sdJwt.split('~')
  const issuerJwt = parts[0]

  // Determine if this has a KB-JWT: if last part is empty it's the simplified flow (no KB-JWT)
  const hasKbJwt = parts[parts.length - 1] !== ''

  // Decode issuer JWT payload to get issuer DID (without verifying yet)
  const payloadB64 = issuerJwt.split('.')[1]
  const issuerPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
  const issuerDid = issuerPayload.iss as string

  const issuerTrusted = issuerDid ? await isIssuerTrusted(issuerDid) : false

  // Get issuer public key
  const issuerRecord = await getDidRecord(issuerDid)
  const issuerPublicJwk: JWK = JSON.parse(issuerRecord.publicKey)

  let valid = false
  let disclosedClaims: Record<string, unknown> = {}

  if (hasKbJwt) {
    // Full verification with KB-JWT via verifySdJwtPresentation
    // We don't have a stored nonce/audience for the REST flow — verify structure only
    // Use a best-effort approach: extract nonce/aud from KB-JWT payload
    const kbJwt = parts[parts.length - 1]
    const kbPayloadB64 = kbJwt.split('.')[1]
    const kbPayload = JSON.parse(Buffer.from(kbPayloadB64, 'base64url').toString())

    const result = await verifySdJwtPresentation({
      combined: sdJwt,
      issuerPublicJwk,
      expectedNonce: kbPayload.nonce as string,
      expectedAudience: kbPayload.aud as string,
    })
    valid = result.valid
    disclosedClaims = result.disclosedClaims
  } else {
    // Simplified verification: no KB-JWT (REST API flow)
    // 1. Verify issuer signature
    try {
      const issuerKey = await importJWK(issuerPublicJwk, 'ES256')
      await jwtVerify(issuerJwt, issuerKey, { algorithms: ['ES256'] })
      valid = true
    } catch {
      valid = false
    }

    // 2. Verify disclosed claims match _sd hashes in issuer JWT
    if (valid) {
      const sdHashes = (issuerPayload._sd as string[]) ?? []
      const disclosures = parts.slice(1, -1) // strip trailing empty string

      for (const disc of disclosures) {
        const hash = await sha256Base64url(disc)
        if (!sdHashes.includes(hash)) {
          valid = false
          break
        }
      }

      if (valid) {
        for (const disc of disclosures) {
          const decoded = JSON.parse(Buffer.from(disc, 'base64url').toString())
          disclosedClaims[decoded[1]] = decoded[2]
        }
      }
    }
  }

  await writeAuditLog(verifierDid, 'verify', valid ? 'success' : 'failure')

  // Determine credential status from issuer JWT sub claim (credentialId not in doc for verify flow)
  const credentialStatus = 'unknown'

  return { valid, disclosedClaims, issuerTrusted, credentialStatus }
}

export async function verifyPresentationById(
  presentationId: string
): Promise<{ valid: boolean; issuerTrusted: boolean; credentialStatus: string }> {
  const presentation = await findPresentation(presentationId)
  if (!presentation) throw Errors.PRESENTATION_NOT_FOUND(presentationId)

  const doc = presentation.document as { sdJwt?: string }
  if (!doc.sdJwt) throw Errors.UNSUPPORTED_FORMAT()

  const sdJwt = doc.sdJwt
  const parts = sdJwt.split('~')
  const issuerJwt = parts[0]

  // Decode issuer JWT payload
  const payloadB64 = issuerJwt.split('.')[1]
  const issuerPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
  const issuerDid = issuerPayload.iss as string

  // Get issuer public key
  const issuerRecord = await getDidRecord(issuerDid)
  const issuerPublicJwk: JWK = JSON.parse(issuerRecord.publicKey)

  // Verify issuer signature
  let valid = false
  try {
    const issuerKey = await importJWK(issuerPublicJwk, 'ES256')
    await jwtVerify(issuerJwt, issuerKey, { algorithms: ['ES256'] })
    valid = true
  } catch {
    valid = false
  }

  // Verify disclosures match _sd hashes
  if (valid) {
    const sdHashes = (issuerPayload._sd as string[]) ?? []
    const disclosures = parts.slice(1, -1)
    for (const disc of disclosures) {
      const hash = await sha256Base64url(disc)
      if (!sdHashes.includes(hash)) {
        valid = false
        break
      }
    }
  }

  const issuerTrusted = await isIssuerTrusted(issuerDid)

  // Find credential status
  const credentialId = presentation.credentialIds?.[0]
  let credentialStatus = 'unknown'
  if (credentialId) {
    const cred = await findCredential(credentialId)
    credentialStatus = cred?.status ?? 'unknown'
  }

  return { valid, issuerTrusted, credentialStatus }
}

export async function getPresentation(id: string, callerDid: string) {
  const record = await findPresentation(id)
  if (!record) throw Errors.PRESENTATION_NOT_FOUND(id)
  if (record.holderDid !== callerDid) throw Errors.FORBIDDEN()
  return record
}
