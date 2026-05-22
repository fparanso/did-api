// src/domains/did/repository.ts
import { sql } from '../../shared/db.js'
import type { DidRecord } from '../../shared/types.js'

export async function insertDid(record: Omit<DidRecord, 'createdAt' | 'deactivatedAt'>): Promise<void> {
  await sql`
    INSERT INTO dids (id, role, document, public_key, private_key, bls_public_key, bls_private_key)
    VALUES (
      ${record.id}, ${record.role}, ${sql.json(record.document as any)},
      ${record.publicKey}, ${record.privateKey},
      ${record.blsPublicKey ?? null}, ${record.blsPrivateKey ?? null}
    )
  `
}

export async function findDid(id: string): Promise<DidRecord | null> {
  const [row] = await sql`
    SELECT id, role, document, public_key, private_key,
           bls_public_key, bls_private_key, created_at, deactivated_at
    FROM dids WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id,
    role: row.role,
    document: row.document,
    publicKey: row.publicKey,
    privateKey: row.privateKey,
    blsPublicKey: row.blsPublicKey ?? null,
    blsPrivateKey: row.blsPrivateKey ?? null,
    createdAt: row.createdAt,
    deactivatedAt: row.deactivatedAt ?? null,
  }
}

export async function deactivateDid(id: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE dids SET deactivated_at = now()
    WHERE id = ${id} AND deactivated_at IS NULL
    RETURNING id
  `
  return !!row
}
