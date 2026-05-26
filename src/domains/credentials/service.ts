// src/domains/credentials/service.ts
import { randomUUID } from 'crypto'
import { decryptKey } from '../../shared/crypto/keys.js'
import { generateP256KeyPair } from '../../shared/crypto/p256.js'
import { issueSdJwt } from '../../shared/crypto/sd-jwt.js'
import { buildIssuerSigned } from '../../shared/crypto/mdoc.js'
import { isIssuerTrusted } from '../trust/service.js'
import { getDidRecord } from '../did/service.js'
import {
  insertCredential,
  findCredential,
  listCredentialsByIssuer,
  revokeCredential,
  getNextStatusIndex,
  getAllCredentialsByStatusListId,
} from './repository.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'

export async function issueCredential(
  issuerDid: string,
  subjectDid: string,
  credentialType: string[],
  claims: Record<string, unknown>,
  expiresAt?: Date
) {
  if (!(await isIssuerTrusted(issuerDid))) throw Errors.ISSUER_NOT_TRUSTED()

  const issuerRecord = await getDidRecord(issuerDid)
  await getDidRecord(subjectDid) // validates subject exists

  // Decrypt issuer's P-256 private key
  const privKeyJson = await decryptKey(issuerRecord.privateKey)
  const issuerPrivateJwk = JSON.parse(privKeyJson)

  // Parse the issuer's public JWK (stored as JSON string)
  const issuerPublicJwk = JSON.parse(issuerRecord.publicKey)

  // Generate ephemeral holder P-256 key for mdoc device binding
  const holderKp = await generateP256KeyPair()

  const id = `urn:uuid:${randomUUID()}`

  // Issue SD-JWT VC
  const sdJwt = await issueSdJwt({
    issuerPrivateJwk,
    issuerDid,
    subjectDid,
    vct: credentialType[0],
    claims,
    holderPublicJwk: holderKp.publicJwk,
  })

  // Issue mso_mdoc (ISO 18013-5 mDL format)
  const mdoc = await buildIssuerSigned({
    issuerPrivateJwk,
    issuerDid,
    docType: 'org.iso.18013.5.1.mDL',
    nameSpaces: { 'org.iso.18013.5.1': claims },
    holderPublicJwk: holderKp.publicJwk,
  })

  // Assign a Token Status List index
  const statusListIndex = await getNextStatusIndex()

  // Build W3C VC-shaped document for API compatibility
  const document = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      { '@vocab': 'https://example.org/vocab#' },
    ],
    id,
    type: ['VerifiableCredential', ...credentialType],
    issuer: issuerDid,
    credentialSubject: { id: subjectDid, ...claims },
    ...(expiresAt ? { expirationDate: expiresAt.toISOString() } : {}),
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'ecdsa-sd-2023',
    },
  }

  await insertCredential({
    id,
    issuerDid,
    subjectDid,
    type: ['VerifiableCredential', ...credentialType],
    claims,
    document,
    status: 'active',
    expiresAt: expiresAt ?? null,
    sdJwt,
    mdoc,
    mdocDocType: 'org.iso.18013.5.1.mDL',
    deviceKey: holderKp.publicJwk as Record<string, unknown>,
    statusListId: 'default',
    statusListIndex,
  })
  await writeAuditLog(issuerDid, 'issue', 'success', id)
  return document
}

export async function getCredential(id: string, callerDid: string) {
  const record = await findCredential(id)
  if (!record) throw Errors.CREDENTIAL_NOT_FOUND(id)
  if (record.issuerDid !== callerDid && record.subjectDid !== callerDid) {
    throw Errors.FORBIDDEN()
  }
  return record
}

export async function listCredentials(issuerDid: string) {
  return listCredentialsByIssuer(issuerDid)
}

export async function revokeCredentialById(id: string, issuerDid: string) {
  const ok = await revokeCredential(id, issuerDid)
  if (!ok) throw Errors.CREDENTIAL_NOT_FOUND(id)
  await writeAuditLog(issuerDid, 'revoke', 'success', id)
}

export async function getCredentialStatus(id: string) {
  const record = await findCredential(id)
  if (!record) throw Errors.CREDENTIAL_NOT_FOUND(id)
  return { id, status: record.status }
}

export async function buildStatusList(id: string): Promise<string> {
  const credentials = await getAllCredentialsByStatusListId(id)

  const maxIndex = credentials.reduce(
    (max, c) => Math.max(max, c.statusListIndex ?? 0),
    0
  )
  const bits = new Uint8Array(Math.ceil((maxIndex + 1) / 8))

  for (const cred of credentials) {
    if (cred.status === 'revoked' && cred.statusListIndex !== null) {
      const byteIdx = Math.floor(cred.statusListIndex / 8)
      const bitIdx = cred.statusListIndex % 8
      bits[byteIdx] |= (1 << bitIdx)
    }
  }

  const encodedList = Buffer.from(bits).toString('base64url')

  const { SignJWT } = await import('jose')
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  return new SignJWT({ statusPurpose: 'revocation', encodedList })
    .setProtectedHeader({ alg: 'HS256', typ: 'statuslist+jwt' })
    .setIssuer(process.env.ISSUER_HOST ?? 'http://localhost:3000')
    .setIssuedAt()
    .sign(secret)
}
