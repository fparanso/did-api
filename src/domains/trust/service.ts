// src/domains/trust/service.ts
import { randomUUID } from 'crypto'
import {
  insertAttestation,
  findActiveAttestation,
  listTrustedIssuers,
  revokeAttestation,
} from './repository.js'
import { getDidRecord } from '../did/service.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'

export async function attestIssuer(
  attesterDid: string,
  issuerDid: string,
  expiresAt?: Date
) {
  await getDidRecord(attesterDid)
  await getDidRecord(issuerDid)

  const id = `urn:uuid:${randomUUID()}`
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    type: ['VerifiableCredential', 'IssuerAttestation'],
    issuer: attesterDid,
    credentialSubject: { id: issuerDid, isAuthorizedIssuer: true },
    ...(expiresAt ? { expirationDate: expiresAt.toISOString() } : {}),
  }
  await insertAttestation({
    id,
    attesterDid,
    issuerDid,
    credential,
    status: 'active',
    expiresAt: expiresAt ?? null,
  })
  await writeAuditLog(attesterDid, 'attest', 'success', id)
  return { id, credential }
}

export async function isIssuerTrusted(issuerDid: string): Promise<boolean> {
  const attestation = await findActiveAttestation(issuerDid)
  return attestation !== null
}

export async function getTrustedIssuers() {
  return listTrustedIssuers()
}

export async function revokeIssuerAttestation(id: string, attesterDid: string) {
  const ok = await revokeAttestation(id, attesterDid)
  if (!ok) throw Errors.ATTESTATION_NOT_FOUND(id)
  await writeAuditLog(attesterDid, 'revoke', 'success', id)
}
