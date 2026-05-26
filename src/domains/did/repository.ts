// src/domains/did/repository.ts
import { sql } from '../../shared/db.js'
import type { DidRecord } from '../../shared/types.js'

export async function insertDid(record: Omit<DidRecord, 'createdAt' | 'deactivatedAt'>): Promise<void> {
  await sql`
    INSERT INTO dids (id, role, document, public_key, private_key)
    VALUES (
      ${record.id}, ${record.role}, ${sql.json(record.document as any)},
      ${record.publicKey}, ${record.privateKey}
    )
  `
}

export async function findDid(id: string): Promise<DidRecord | null> {
  const [row] = await sql`
    SELECT id, role, document, public_key, private_key, created_at, deactivated_at
    FROM dids WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id,
    role: row.role,
    document: row.document,
    publicKey: row.public_key,
    privateKey: row.private_key,
    createdAt: row.created_at,
    deactivatedAt: row.deactivated_at ?? null,
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
