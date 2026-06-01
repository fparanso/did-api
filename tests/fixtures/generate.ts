// tests/fixtures/generate.ts
// Utility script to regenerate static test fixtures (run manually, not as part of the test suite)
import { generateDidKey } from '../../src/shared/crypto/did-key'
import { writeFile, mkdir } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

async function generateFixture(role: string) {
  const { did, publicKeyJwk, privateKeyJwk, document } = await generateDidKey()
  return { did, role, document, publicKeyJwk, privateKeyJwk }
}

const issuer = await generateFixture('issuer')
const subject = await generateFixture('subject')
const attester = await generateFixture('attester')
const verifier = await generateFixture('verifier')

await mkdir(__dirname, { recursive: true })
await writeFile(join(__dirname, 'issuer-did.json'), JSON.stringify(issuer, null, 2))
await writeFile(join(__dirname, 'subject-did.json'), JSON.stringify(subject, null, 2))
await writeFile(join(__dirname, 'attester-did.json'), JSON.stringify(attester, null, 2))
await writeFile(join(__dirname, 'verifier-did.json'), JSON.stringify(verifier, null, 2))

console.log('Fixtures generated.')
