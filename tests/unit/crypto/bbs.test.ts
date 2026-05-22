// tests/unit/crypto/bbs.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { signCredential, deriveProof, verifyProof } from '../../../src/shared/crypto/bbs'
import { generateBlsKeyPair, buildDidDocument } from '../../../src/shared/crypto/did-key'
import { initContextLoader, setDidResolver } from '../../../src/shared/jsonld/loader'

const ISSUER_DID = 'did:key:zUC7TestIssuer123'

describe('BBS+ sign / derive / verify', () => {
  let blsPublicKey: string
  let blsSecretKey: string
  let signedVc: object

  beforeAll(async () => {
    await initContextLoader()

    const bls = await generateBlsKeyPair(ISSUER_DID)
    blsPublicKey = bls.publicKeyMultibase
    blsSecretKey = bls.secretKeyMultibase

    // Set DID resolver to return issuer doc with BLS key
    const resolverDoc = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1',
      ],
      id: ISSUER_DID,
      verificationMethod: [
        {
          id: `${ISSUER_DID}#${blsPublicKey}`,
          type: 'Multikey',
          controller: ISSUER_DID,
          publicKeyMultibase: blsPublicKey,
        }
      ],
      assertionMethod: [`${ISSUER_DID}#${blsPublicKey}`],
    }
    setDidResolver(async (_did) => resolverDoc)
  })

  test('signCredential returns a VC with a DataIntegrityProof', async () => {
    const credential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        // Inline @vocab so custom terms (name, degree, gpa) are valid in safe-mode JSON-LD expansion
        { '@vocab': 'https://example.org/vocab#' },
      ],
      id: 'urn:uuid:test-cred-001',
      type: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      credentialSubject: {
        id: 'did:key:zSubjectTest',
        name: 'Alice',
        degree: 'BSc',
        gpa: '3.9',
      },
    }

    signedVc = await signCredential(credential, {
      id: `${ISSUER_DID}#${blsPublicKey}`,
      controller: ISSUER_DID,
      publicKeyMultibase: blsPublicKey,
      secretKeyMultibase: blsSecretKey,
    })

    expect((signedVc as any).proof).toBeTruthy()
    expect((signedVc as any).proof.type).toBe('DataIntegrityProof')
    expect((signedVc as any).proof.cryptosuite).toContain('bbs')
  })

  test('deriveProof discloses only selected claims', async () => {
    const derived = await deriveProof(signedVc, ['/credentialSubject/name'])
    expect((derived as any).credentialSubject).toBeTruthy()
    // name should be present, gpa should not be (it's hidden)
    expect((derived as any).credentialSubject.name).toBe('Alice')
    // gpa is not in the selective pointers so it should be absent
    expect((derived as any).credentialSubject.gpa).toBeUndefined()
  })

  test('verifyProof returns true for a valid derived proof', async () => {
    const derived = await deriveProof(signedVc, ['/credentialSubject/name'])
    const valid = await verifyProof(derived)
    expect(valid).toBe(true)
  })
})
