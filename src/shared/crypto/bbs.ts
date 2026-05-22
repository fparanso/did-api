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
    cryptosuite: createSignCryptosuite(),
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
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite(),
  })

  // BBS+ derived VCs may omit `issuer` (selective disclosure), so we verify
  // the DataIntegrity proof directly via jsonld-signatures rather than using
  // vc.verify / vc.verifyCredential which require the `issuer` field.
  const result = await jldSig.verify(credentialOrPresentation, {
    suite,
    purpose: new (jldSig as any).purposes.AssertionProofPurpose(),
    documentLoader: getDocumentLoader(),
  })
  return result.verified
}
