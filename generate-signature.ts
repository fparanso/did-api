#!/usr/bin/env bun
// generate-signature.ts
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { decryptKey } from './src/shared/crypto/keys.js';
import { sql } from './src/shared/db.js';

function printUsage() {
  console.log(`
Usage:
  bun run generate-signature.ts <did> <challengeId>

Example:
  bun run generate-signature.ts "did:key:z6MknwjrNSCBRBYdCgSXPHFQXNyisvEWM3SuVYnT6d215XUC" "af003fcc-5012-42f9-b508-4f7e4d88236a"
`);
}

async function main() {
  const args = process.argv.slice(2);
  const did = args[0];
  const challengeId = args[1];

  if (!did || !challengeId) {
    printUsage();
    process.exit(1);
  }

  try {
    // 1. Fetch challenge details from local database
    const [challengeRow] = await sql`
      SELECT nonce FROM auth_challenges
      WHERE id = ${challengeId}::uuid AND did = ${did}
    `;

    if (!challengeRow) {
      console.error(`Error: Challenge not found for ID "${challengeId}" and DID "${did}".`);
      process.exit(1);
    }

    const nonce = challengeRow.nonce;

    // 2. Fetch DID private key
    const [didRow] = await sql`
      SELECT private_key FROM dids
      WHERE id = ${did} AND deactivated_at IS NULL
    `;

    if (!didRow) {
      console.error(`Error: Active DID record not found for "${did}".`);
      process.exit(1);
    }

    // 3. Decrypt the private key using the local environment secret
    const privateKeyMultibase = await decryptKey(didRow.privateKey);
    const publicKeyMultibase = did.replace('did:key:', '');

    // 4. Load verification key pair
    const keyPair = await Ed25519VerificationKey2020.from({
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase,
      privateKeyMultibase,
    });

    // 5. Sign message of form "<did>:<nonce>"
    const signer = keyPair.signer();
    const message = new TextEncoder().encode(`${did}:${nonce}`);
    const signatureBytes = await signer.sign({ data: message });

    // 6. Output signature
    const signature = Buffer.from(signatureBytes).toString('base64');
    
    console.log(signature);
  } catch (error: any) {
    console.error('An error occurred:', error.message || error);
    process.exit(1);
  } finally {
    await sql.end();
  }
}

main().catch(async (err) => {
  console.error(err);
  await sql.end();
  process.exit(1);
});
