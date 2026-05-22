// tests/fixtures/generate.ts
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../src/shared/crypto/did-key'
import { writeFile, mkdir } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

async function generateFixture(role: string, withBls = false) {
  const { did, publicKeyMultibase, privateKeyMultibase } = await generateDidKey()
  let blsPublicKey: string | undefined
  let blsSecretKey: string | undefined
  if (withBls) {
    const bls = await generateBlsKeyPair(did)
    blsPublicKey = bls.publicKeyMultibase
    blsSecretKey = bls.secretKeyMultibase
  }
  const document = buildDidDocument(did, publicKeyMultibase, blsPublicKey)
  return { did, role, document, publicKeyMultibase, privateKeyMultibase, blsPublicKey, blsSecretKey }
}

const issuer = await generateFixture('issuer', true)
const subject = await generateFixture('subject')
const attester = await generateFixture('attester')
const verifier = await generateFixture('verifier')

await mkdir(__dirname, { recursive: true })
await writeFile(join(__dirname, 'issuer-did.json'), JSON.stringify(issuer, null, 2))
await writeFile(join(__dirname, 'subject-did.json'), JSON.stringify(subject, null, 2))
await writeFile(join(__dirname, 'attester-did.json'), JSON.stringify(attester, null, 2))
await writeFile(join(__dirname, 'verifier-did.json'), JSON.stringify(verifier, null, 2))

console.log('Fixtures generated.')
