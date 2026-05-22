// src/shared/crypto/did-key.ts
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { generateBbsKeyPair, from as blsFrom } from '@digitalbazaar/bls12-381-multikey'

export interface DidKeyResult {
  did: string
  publicKeyMultibase: string
  privateKeyMultibase: string
}

export async function generateDidKey(): Promise<DidKeyResult> {
  // Generate Ed25519 key pair — did:key DID is derived from the public key multibase
  const keyPair = await Ed25519VerificationKey2020.generate()
  // publicKeyMultibase starts with 'z6Mk' for Ed25519
  const did = `did:key:${keyPair.publicKeyMultibase}`
  keyPair.controller = did
  keyPair.id = `${did}#${keyPair.publicKeyMultibase}`
  return {
    did,
    publicKeyMultibase: keyPair.publicKeyMultibase!,
    privateKeyMultibase: keyPair.privateKeyMultibase!,
  }
}

export interface BlsKeyResult {
  publicKeyMultibase: string
  secretKeyMultibase: string
}

export async function generateBlsKeyPair(controller: string): Promise<BlsKeyResult> {
  const keyPair = await generateBbsKeyPair({
    algorithm: 'BBS-BLS12-381-SHA-256',
    controller,
  })
  return {
    publicKeyMultibase: keyPair.publicKeyMultibase,
    secretKeyMultibase: keyPair.secretKeyMultibase,
  }
}

export function buildDidDocument(
  did: string,
  publicKeyMultibase: string,
  blsPublicKeyMultibase?: string
): Record<string, unknown> {
  const keyId = `${did}#${publicKeyMultibase}`
  const contexts: string[] = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
  ]
  const verificationMethods: object[] = [{
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase,
  }]

  if (blsPublicKeyMultibase) {
    contexts.push('https://w3id.org/security/multikey/v1')
    verificationMethods.push({
      id: `${did}#${blsPublicKeyMultibase}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: blsPublicKeyMultibase,
    })
  }

  return {
    '@context': contexts,
    id: did,
    verificationMethod: verificationMethods,
    authentication: [keyId],
    assertionMethod: blsPublicKeyMultibase
      ? [keyId, `${did}#${blsPublicKeyMultibase}`]
      : [keyId],
    capabilityInvocation: [keyId],
    capabilityDelegation: [keyId],
  }
}
