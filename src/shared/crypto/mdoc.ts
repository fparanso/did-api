// src/shared/crypto/mdoc.ts
import { encode, decode, Tag } from 'cbor2'
import { importJWK } from 'jose'
import type { JWK } from 'jose'

const COSE_SIGN1_TAG = 18

// Convert DER-encoded ECDSA signature to 64-byte raw r||s
function derToRaw(der: Uint8Array): Uint8Array {
  let offset = 2 // skip 0x30, length
  offset++ // skip 0x02
  const rLen = der[offset++]
  let r = der.slice(offset, offset + rLen)
  offset += rLen
  offset++ // skip 0x02
  const sLen = der[offset++]
  let s = der.slice(offset, offset + sLen)

  // Remove leading zero padding
  if (r[0] === 0x00) r = r.slice(1)
  if (s[0] === 0x00) s = s.slice(1)

  // Pad to 32 bytes
  const raw = new Uint8Array(64)
  raw.set(r, 32 - r.length)
  raw.set(s, 64 - s.length)
  return raw
}

// Convert 64-byte raw r||s to DER
function rawToDer(raw: Uint8Array): Uint8Array {
  let r = raw.slice(0, 32)
  let s = raw.slice(32, 64)

  // Add leading zero if high bit set
  if (r[0] & 0x80) r = new Uint8Array([0x00, ...r])
  if (s[0] & 0x80) s = new Uint8Array([0x00, ...s])

  const rSeq = new Uint8Array([0x02, r.length, ...r])
  const sSeq = new Uint8Array([0x02, s.length, ...s])
  const body = new Uint8Array([...rSeq, ...sSeq])
  return new Uint8Array([0x30, body.length, ...body])
}

// Detect if a signature buffer is DER-encoded (starts with 0x30)
function isDerSignature(sig: Uint8Array): boolean {
  return sig[0] === 0x30
}

async function coseSign1(payload: Uint8Array, privateJwk: JWK): Promise<Uint8Array> {
  const protectedMap = new Map([[1, -7]]) // alg: ES256
  const protectedBstr = encode(protectedMap)

  const sigStructure = encode(['Signature1', protectedBstr, new Uint8Array(0), payload])

  const cryptoKey = (await importJWK(privateJwk, 'ES256')) as CryptoKey
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, sigStructure)
  )
  // Normalize to 64-byte raw r||s (COSE requirement)
  const sig = isDerSignature(sigBytes) ? derToRaw(sigBytes) : sigBytes

  return encode(new Tag(COSE_SIGN1_TAG, [protectedBstr, {}, payload, sig]))
}

// Convert a value to a plain Uint8Array (not Buffer) so cbor2 encodes it as a bstr
function toUint8Array(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
  throw new Error(`Expected Uint8Array, got ${typeof v}`)
}

async function coseVerify1(coseBytes: Uint8Array, publicJwk: JWK): Promise<Uint8Array> {
  const tagged = decode(coseBytes) as Tag
  const [rawProtectedBstr, , rawPayload, rawSig] = tagged.contents as [unknown, unknown, unknown, unknown]

  // Bun's cbor2 decode returns Buffer (subclass of Uint8Array) which cbor2 encodes as an Object.
  // We must convert to plain Uint8Array so cbor2 encodes them as CBOR byte strings.
  const protectedBstr = toUint8Array(rawProtectedBstr)
  const payload = toUint8Array(rawPayload)
  const sig = toUint8Array(rawSig)

  const sigStructure = encode(['Signature1', protectedBstr, new Uint8Array(0), payload])

  const cryptoKey = (await importJWK(publicJwk, 'ES256')) as CryptoKey

  // Try raw format first (Bun), fall back to DER (Node.js)
  let ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, sig, sigStructure)
  if (!ok) {
    // Try DER format as fallback
    const derSig = rawToDer(sig)
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, derSig, sigStructure)
  }
  if (!ok) throw new Error('COSE_Sign1 verification failed')
  return payload
}

export interface IssuerSignedOptions {
  issuerPrivateJwk: JWK
  issuerDid: string
  docType: string
  nameSpaces: Record<string, Record<string, unknown>>
  holderPublicJwk: JWK
}

export async function buildIssuerSigned(opts: IssuerSignedOptions): Promise<string> {
  const { issuerPrivateJwk, docType, nameSpaces, holderPublicJwk } = opts

  const valueDigests: Record<string, Record<number, Uint8Array>> = {}
  const issuerNameSpaces: Record<string, unknown[]> = {}

  for (const [ns, elements] of Object.entries(nameSpaces)) {
    valueDigests[ns] = {}
    issuerNameSpaces[ns] = []
    let digestId = 0

    for (const [key, value] of Object.entries(elements)) {
      const random = crypto.getRandomValues(new Uint8Array(16))
      const item = { digestID: digestId, random, elementIdentifier: key, elementValue: value }
      const itemBytes = encode(item)
      // IssuerSignedItem is CBOR-tagged 24 (embedded CBOR)
      const itemTagged = new Tag(24, itemBytes)
      issuerNameSpaces[ns].push(encode(itemTagged))

      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', itemBytes))
      valueDigests[ns][digestId] = digest
      digestId++
    }
  }

  // Build holder COSE key (EC2 key type)
  const holderCoseKey = new Map<number, unknown>([
    [1, 2], // kty: EC2
    [-1, 1], // crv: P-256
    [-2, Buffer.from(holderPublicJwk.x!, 'base64url')], // x
    [-3, Buffer.from(holderPublicJwk.y!, 'base64url')], // y
  ])

  const mso = {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests,
    docType,
    deviceKeyInfo: { deviceKey: holderCoseKey },
  }

  const msoBytes = encode(mso)
  const issuerAuth = await coseSign1(msoBytes, issuerPrivateJwk)

  const issuerSigned = { nameSpaces: issuerNameSpaces, issuerAuth }
  return Buffer.from(encode(issuerSigned)).toString('base64url')
}

export interface DeviceResponseVerifyResult {
  valid: boolean
  claims?: Record<string, Record<string, unknown>>
  error?: string
}

export async function verifyDeviceResponse(opts: {
  issuerSignedBase64url: string
  issuerPublicJwk: JWK
  expectedDocType: string
}): Promise<DeviceResponseVerifyResult> {
  try {
    const bytes = Buffer.from(opts.issuerSignedBase64url, 'base64url')
    const issuerSigned = decode(bytes) as {
      nameSpaces: Record<string, Uint8Array[]>
      issuerAuth: Uint8Array
    }

    // Verify COSE_Sign1
    const msoBytes = await coseVerify1(issuerSigned.issuerAuth, opts.issuerPublicJwk)
    const mso = decode(msoBytes) as {
      docType: string
      digestAlgorithm: string
      valueDigests: Record<string, Record<number, Uint8Array>>
    }

    if (mso.docType !== opts.expectedDocType) {
      return { valid: false, error: `docType mismatch: ${mso.docType}` }
    }

    // Verify digests and extract claims
    const claims: Record<string, Record<string, unknown>> = {}
    for (const [ns, items] of Object.entries(issuerSigned.nameSpaces)) {
      claims[ns] = {}
      const expectedDigests = mso.valueDigests[ns] ?? {}
      for (const itemBytes of items) {
        const itemTagged = decode(itemBytes) as Tag
        const innerBytes = itemTagged.contents as Uint8Array
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', innerBytes))
        const item = decode(innerBytes) as {
          digestID: number
          elementIdentifier: string
          elementValue: unknown
        }
        const expected = expectedDigests[item.digestID]
        if (!expected || Buffer.compare(Buffer.from(digest), Buffer.from(expected)) !== 0) {
          return { valid: false, error: `Digest mismatch for ${item.elementIdentifier}` }
        }
        claims[ns][item.elementIdentifier] = item.elementValue
      }
    }

    return { valid: true, claims }
  } catch (err) {
    return { valid: false, error: String(err) }
  }
}
