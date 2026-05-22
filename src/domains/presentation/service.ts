// src/domains/presentation/service.ts
import { randomUUID } from 'crypto'
import * as vcLib from '@digitalbazaar/vc'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'
import { deriveProof, verifyProof } from '../../shared/crypto/bbs.js'
import { decryptKey } from '../../shared/crypto/keys.js'
import { getDidRecord } from '../did/service.js'
import { findCredential } from '../credentials/repository.js'
import { isIssuerTrusted } from '../trust/service.js'
import { insertPresentation, findPresentation } from './repository.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'
import { getDocumentLoader } from '../../shared/jsonld/loader.js'

export async function deriveSelectivePresentation(
  holderDid: string,
  credentialId: string,
  revealedClaims: string[]
) {
  const credential = await findCredential(credentialId)
  if (!credential) throw Errors.CREDENTIAL_NOT_FOUND(credentialId)
  if (credential.subjectDid !== holderDid) throw Errors.FORBIDDEN()
  if (credential.status === 'revoked') throw Errors.CREDENTIAL_REVOKED()

  // Build selective pointer paths
  const selectivePointers = revealedClaims.map(c => `/credentialSubject/${c}`)
  const derived = await deriveProof(credential.document, selectivePointers)

  // Build holder-binding VP with Ed25519 signature
  const holderRecord = await getDidRecord(holderDid)
  const privateKeyMultibase = await decryptKey(holderRecord.privateKey)

  const keyPair = await Ed25519VerificationKey2020.from({
    id: `${holderDid}#${holderRecord.publicKey}`,
    controller: holderDid,
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: holderRecord.publicKey,
    privateKeyMultibase,
  })

  const holderSuite = new Ed25519Signature2020({ key: keyPair })
  const challenge = randomUUID()

  const presentation = vcLib.createPresentation({
    verifiableCredential: derived,
    holder: holderDid,
  })

  const signedVp = await vcLib.signPresentation({
    presentation,
    suite: holderSuite,
    challenge,
    documentLoader: getDocumentLoader(),
  })

  const id = `urn:uuid:${randomUUID()}`
  const disclosedClaims = Object.fromEntries(
    revealedClaims.map(k => [
      k,
      (credential.claims as Record<string, unknown>)[k],
    ])
  )

  await insertPresentation({
    id,
    holderDid,
    credentialIds: [credentialId],
    document: signedVp as Record<string, unknown>,
    disclosedClaims,
  })
  await writeAuditLog(holderDid, 'issue', 'success', id)
  return { id, presentation: signedVp, disclosedClaims }
}

export async function verifyVp(
  presentationDoc: Record<string, unknown>,
  verifierDid: string
): Promise<{
  valid: boolean
  disclosedClaims: unknown
  issuerTrusted: boolean
  credentialStatus: string
}> {
  // Extract issuer DID from the embedded VC
  const embeddedVc = Array.isArray(presentationDoc.verifiableCredential)
    ? (presentationDoc.verifiableCredential as any[])[0]
    : presentationDoc.verifiableCredential

  const issuerDid =
    typeof embeddedVc?.issuer === 'string'
      ? embeddedVc.issuer
      : (embeddedVc?.issuer as any)?.id

  const credentialId = embeddedVc?.id

  const issuerTrusted = issuerDid ? await isIssuerTrusted(issuerDid) : false

  let credentialStatus = 'unknown'
  if (credentialId) {
    const record = await findCredential(credentialId)
    credentialStatus = record?.status ?? 'unknown'
  }
  if (credentialStatus === 'revoked') throw Errors.CREDENTIAL_REVOKED()

  const valid = await verifyProof(presentationDoc)
  await writeAuditLog(verifierDid, 'verify', valid ? 'success' : 'failure')

  return {
    valid,
    disclosedClaims: embeddedVc?.credentialSubject ?? {},
    issuerTrusted,
    credentialStatus,
  }
}

export async function getPresentation(id: string, callerDid: string) {
  const record = await findPresentation(id)
  if (!record) throw Errors.PRESENTATION_NOT_FOUND(id)
  if (record.holderDid !== callerDid) throw Errors.FORBIDDEN()
  return record
}
