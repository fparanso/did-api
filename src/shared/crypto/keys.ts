// src/shared/crypto/keys.ts
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

async function getKey(): Promise<CryptoKey> {
  const secret = process.env.KEY_ENCRYPTION_SECRET
  if (!secret || secret.length !== 64) {
    throw new Error('KEY_ENCRYPTION_SECRET must be a 64-char hex string (32 bytes)')
  }
  return crypto.subtle.importKey(
    'raw', hexToBytes(secret) as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['encrypt', 'decrypt']
  )
}

export async function encryptKey(value: string): Promise<string> {
  const key = await getKey()
  const iv = crypto.getRandomValues(new Uint8Array(12)) as Uint8Array<ArrayBuffer>
  const data = new TextEncoder().encode(value)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
  const ivB64 = Buffer.from(iv).toString('base64')
  const encB64 = Buffer.from(encrypted).toString('base64')
  return `${ivB64}:${encB64}`
}

export async function decryptKey(stored: string): Promise<string> {
  const [ivB64, encB64] = stored.split(':')
  if (!ivB64 || !encB64) throw new Error('Invalid encrypted key format')
  const key = await getKey()
  const iv = Buffer.from(ivB64, 'base64')
  const encrypted = Buffer.from(encB64, 'base64')
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted)
  return new TextDecoder().decode(decrypted)
}
