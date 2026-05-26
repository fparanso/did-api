// src/shared/crypto/did-key.ts
import type { JWK } from 'jose'
import { generateP256KeyPair, didKeyFromPublicJwk } from './p256.js'

export function buildDidDocument(did: string, publicKeyJwk: JWK) {
  const keyId = `${did}#key-1`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1',
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Multikey',
        controller: did,
        publicKeyJwk,
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    keyAgreement: [keyId],
  }
}

export async function generateDidKey(existingDid?: string) {
  const { privateJwk, publicJwk } = await generateP256KeyPair()
  const did = existingDid ?? didKeyFromPublicJwk(publicJwk)
  const document = buildDidDocument(did, publicJwk)
  return { did, publicKeyJwk: publicJwk, privateKeyJwk: privateJwk, document }
}
