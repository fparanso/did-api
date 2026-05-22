// src/shared/crypto/bbs.ts
import {
  createSignCryptosuite,
  createDiscloseCryptosuite,
  createVerifyCryptosuite,
} from '@digitalbazaar/bbs-2023-cryptosuite'
import { DataIntegrityProof } from '@digitalbazaar/data-integrity'
import { from as blsFrom } from '@digitalbazaar/bls12-381-multikey'
import * as vc from '@digitalbazaar/vc'
import * as jldSig from 'jsonld-signatures'
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'
import { getDocumentLoader } from '../jsonld/loader.js'

export interface BlsKeyPairInput {
  id: string
  controller: string
  publicKeyMultibase: string
  secretKeyMultibase: string
}

export async function signCredential(
  credential: object,
  keyPairInput: BlsKeyPairInput
): Promise<object> {
  const keyPair = await blsFrom({
    ...keyPairInput,
    type: 'Multikey',
    algorithm: 'BBS-BLS12-381-SHA-256',
  })
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(),
    cryptosuite: createSignCryptosuite({
      mandatoryPointers: ['/issuer', '/credentialSubject/id'],
    }),
  })
  return vc.issue({ credential, suite, documentLoader: getDocumentLoader() })
}

export async function deriveProof(
  signedVc: object,
  selectivePointers: string[]
): Promise<object> {
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({ selectivePointers }),
  })
  return vc.derive({ verifiableCredential: signedVc, suite, documentLoader: getDocumentLoader() })
}

export async function verifyProof(
  credentialOrPresentation: object
): Promise<boolean> {
  const doc = credentialOrPresentation as Record<string, unknown>
  const documentLoader = getDocumentLoader()

  // Determine if this is a VP (has verifiableCredential field) or a VC
  const isPresentation =
    Array.isArray((doc as any).type)
      ? (doc as any).type.includes('VerifiablePresentation')
      : (doc as any).type === 'VerifiablePresentation'

  if (isPresentation) {
    // Verify embedded VC's BBS+ derived proof
    const embeddedVc = Array.isArray((doc as any).verifiableCredential)
      ? (doc as any).verifiableCredential[0]
      : (doc as any).verifiableCredential

    if (embeddedVc) {
      const bbsSuite = new DataIntegrityProof({
        cryptosuite: createVerifyCryptosuite(),
      })
      const vcResult = await jldSig.verify(embeddedVc, {
        suite: bbsSuite,
        purpose: new (jldSig as any).purposes.AssertionProofPurpose(),
        documentLoader,
      })
      if (!vcResult.verified) return false
    }

    // Verify outer VP holder Ed25519 proof
    const challenge = ((doc as any).proof as Record<string, unknown>)?.challenge as string | undefined
    const vpResult = await jldSig.verify(doc, {
      suite: new Ed25519Signature2020(),
      purpose: new (jldSig as any).purposes.AuthenticationProofPurpose({
        challenge: challenge ?? '',
      }),
      documentLoader,
    })
    return vpResult.verified
  }

  // Single VC verification using BBS+ verify cryptosuite
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite(),
  })
  const result = await jldSig.verify(credentialOrPresentation, {
    suite,
    purpose: new (jldSig as any).purposes.AssertionProofPurpose(),
    documentLoader,
  })
  return result.verified
}
