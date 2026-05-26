// tests/unit/crypto/mdoc.test.ts
import { describe, test, expect } from 'bun:test'
import { generateKeyPair, exportJWK } from 'jose'
import { buildIssuerSigned, verifyDeviceResponse } from '../../../src/shared/crypto/mdoc'

describe('buildIssuerSigned', () => {
  test('returns a non-empty base64url string', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const result = await buildIssuerSigned({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      docType: 'org.iso.18013.5.1.mDL',
      nameSpaces: {
        'org.iso.18013.5.1': { family_name: 'Smith', given_name: 'Alice' },
      },
      holderPublicJwk,
    })

    expect(typeof result).toBe('string')
    expect(result.length).toBeGreaterThan(100)
    // Should be valid base64url
    expect(() => Buffer.from(result, 'base64url')).not.toThrow()
  })

  test('builds CBOR that decodes without error', async () => {
    const { decode } = await import('cbor2')
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const result = await buildIssuerSigned({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      docType: 'org.iso.18013.5.1.mDL',
      nameSpaces: { 'org.iso.18013.5.1': { family_name: 'Smith' } },
      holderPublicJwk,
    })

    const bytes = Buffer.from(result, 'base64url')
    const decoded = decode(bytes)
    expect(decoded).toBeDefined()
    expect(decoded.nameSpaces).toBeDefined()
    expect(decoded.issuerAuth).toBeDefined()
  })
})

describe('verifyDeviceResponse', () => {
  test('returns valid=true for a self-consistent IssuerSigned', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const issuerPublicJwk = await exportJWK(issuerKp.publicKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const mdoc = await buildIssuerSigned({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      docType: 'org.iso.18013.5.1.mDL',
      nameSpaces: { 'org.iso.18013.5.1': { family_name: 'Smith' } },
      holderPublicJwk,
    })

    const result = await verifyDeviceResponse({
      issuerSignedBase64url: mdoc,
      issuerPublicJwk,
      expectedDocType: 'org.iso.18013.5.1.mDL',
    })

    expect(result.valid).toBe(true)
    expect(result.claims?.['org.iso.18013.5.1']?.family_name).toBe('Smith')
  })

  test('returns valid=false with wrong issuer key', async () => {
    const issuerKp = await generateKeyPair('ES256', { extractable: true })
    const issuerPrivateJwk = await exportJWK(issuerKp.privateKey)
    const wrongKp = await generateKeyPair('ES256', { extractable: true })
    const wrongPublicJwk = await exportJWK(wrongKp.publicKey)
    const holderKp = await generateKeyPair('ES256', { extractable: true })
    const holderPublicJwk = await exportJWK(holderKp.publicKey)

    const mdoc = await buildIssuerSigned({
      issuerPrivateJwk,
      issuerDid: 'did:key:zIssuer',
      docType: 'org.iso.18013.5.1.mDL',
      nameSpaces: { 'org.iso.18013.5.1': { family_name: 'Smith' } },
      holderPublicJwk,
    })

    const result = await verifyDeviceResponse({
      issuerSignedBase64url: mdoc,
      issuerPublicJwk: wrongPublicJwk,
      expectedDocType: 'org.iso.18013.5.1.mDL',
    })

    expect(result.valid).toBe(false)
  })
})
