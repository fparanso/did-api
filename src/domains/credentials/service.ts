// src/domains/credentials/service.ts
import { randomUUID } from 'crypto'
import { signCredential } from '../../shared/crypto/bbs.js'
import { decryptKey } from '../../shared/crypto/keys.js'
import { isIssuerTrusted } from '../trust/service.js'
import { getDidRecord } from '../did/service.js'
import {
  insertCredential,
  findCredential,
  listCredentialsByIssuer,
  revokeCredential,
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
  if (!issuerRecord.blsPublicKey || !issuerRecord.blsPrivateKey) {
    throw new Error('Issuer does not have a BLS12-381 key pair')
  }
  await getDidRecord(subjectDid) // validates subject exists

  const secretKeyMultibase = await decryptKey(issuerRecord.blsPrivateKey)

  const id = `urn:uuid:${randomUUID()}`
  const credential = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      { '@vocab': 'https://example.org/vocab#' },
    ],
    id,
    type: ['VerifiableCredential', ...credentialType],
    issuer: issuerDid,
    credentialSubject: { id: subjectDid, ...claims },
    ...(expiresAt ? { expirationDate: expiresAt.toISOString() } : {}),
  }

  const signedVc = await signCredential(credential, {
    id: `${issuerDid}#${issuerRecord.blsPublicKey}`,
    controller: issuerDid,
    publicKeyMultibase: issuerRecord.blsPublicKey,
    secretKeyMultibase,
  })

  await insertCredential({
    id,
    issuerDid,
    subjectDid,
    type: ['VerifiableCredential', ...credentialType],
    claims,
    document: signedVc as Record<string, unknown>,
    status: 'active',
    expiresAt: expiresAt ?? null,
  })
  await writeAuditLog(issuerDid, 'issue', 'success', id)
  return signedVc
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
