// src/shared/crypto/p256.ts
import { generateKeyPair, exportJWK } from 'jose'
import type { JWK } from 'jose'

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Encode(bytes: Uint8Array): string {
  let num = BigInt('0x' + Buffer.from(bytes).toString('hex'))
  let result = ''
  while (num > 0n) {
    const rem = Number(num % 58n)
    result = B58_ALPHABET[rem] + result
    num = num / 58n
  }
  for (const byte of bytes) {
    if (byte !== 0) break
    result = '1' + result
  }
  return result
}

export function compressP256Jwk(jwk: JWK): Uint8Array {
  const x = Buffer.from(jwk.x!, 'base64url')
  const y = Buffer.from(jwk.y!, 'base64url')
  const prefix = (y[y.length - 1] & 1) === 0 ? 0x02 : 0x03
  return new Uint8Array([prefix, ...x])
}

// P-256 multicodec prefix: varint encoding of 0x1200
const P256_MULTICODEC = new Uint8Array([0x80, 0x24])

export function didKeyFromPublicJwk(jwk: JWK): string {
  const compressed = compressP256Jwk(jwk)
  const prefixed = new Uint8Array(P256_MULTICODEC.length + compressed.length)
  prefixed.set(P256_MULTICODEC)
  prefixed.set(compressed, P256_MULTICODEC.length)
  return `did:key:z${base58Encode(prefixed)}`
}

export async function generateP256KeyPair(): Promise<{ privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true })
  const privateJwk = await exportJWK(privateKey)
  const publicJwk = await exportJWK(publicKey)
  return { privateJwk, publicJwk }
}
