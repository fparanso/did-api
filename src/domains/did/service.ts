// src/domains/did/service.ts
import { generateDidKey, buildDidDocument } from '../../shared/crypto/did-key.js'
import { encryptKey } from '../../shared/crypto/keys.js'
import { insertDid, findDid, deactivateDid } from './repository.js'
import { Errors } from '../../shared/errors.js'
import type { Role, DidRecord } from '../../shared/types.js'

export async function createDid(role: Role) {
  const { did, publicKeyJwk, privateKeyJwk, document } = await generateDidKey()
  const encryptedPrivateKey = await encryptKey(JSON.stringify(privateKeyJwk))

  await insertDid({
    id: did,
    role,
    document,
    publicKey: JSON.stringify(publicKeyJwk),
    privateKey: encryptedPrivateKey,
  })

  return {
    did,
    role,
    document,
    privateKey: privateKeyJwk, // returned once only, client must store it
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
