// src/domains/did/service.ts
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../shared/crypto/did-key.js'
import { encryptKey } from '../../shared/crypto/keys.js'
import { insertDid, findDid, deactivateDid } from './repository.js'
import { Errors } from '../../shared/errors.js'
import type { Role, DidRecord } from '../../shared/types.js'

export async function createDid(role: Role) {
  const { did, publicKeyMultibase, privateKeyMultibase } = await generateDidKey()
  const encryptedPrivateKey = await encryptKey(privateKeyMultibase)

  let blsPublicKey: string | null = null
  let blsPrivateKey: string | null = null
  let document: Record<string, unknown>

  if (role === 'issuer') {
    const bls = await generateBlsKeyPair(did)
    blsPublicKey = bls.publicKeyMultibase
    blsPrivateKey = await encryptKey(bls.secretKeyMultibase)
    document = buildDidDocument(did, publicKeyMultibase, blsPublicKey)
  } else {
    document = buildDidDocument(did, publicKeyMultibase)
  }

  await insertDid({
    id: did,
    role,
    document,
    publicKey: publicKeyMultibase,
    privateKey: encryptedPrivateKey,
    blsPublicKey,
    blsPrivateKey,
  })

  return {
    did,
    role,
    document,
    privateKey: privateKeyMultibase, // returned once only, client must store it
  }
}

export async function resolveDid(id: string): Promise<Record<string, unknown>> {
  const record = await findDid(id)
  if (!record || record.deactivatedAt) throw Errors.DID_NOT_FOUND(id)
  return record.document
}

export async function getDidRecord(id: string): Promise<DidRecord> {
  const record = await findDid(id)
  if (!record || record.deactivatedAt) throw Errors.DID_NOT_FOUND(id)
  return record
}

export async function deactivate(id: string, callerDid: string) {
  if (id !== callerDid) throw Errors.FORBIDDEN()
  const ok = await deactivateDid(id)
  if (!ok) throw Errors.DID_NOT_FOUND(id)
}
