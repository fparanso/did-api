// src/domains/presentation/repository.ts
import { sql } from '../../shared/db.js'
import type { PresentationRecord } from '../../shared/types.js'

export async function insertPresentation(
  record: Omit<PresentationRecord, 'createdAt'>
): Promise<void> {
  await sql`
    INSERT INTO presentations (id, holder_did, credential_ids, document, disclosed_claims)
    VALUES (
      ${record.id}, ${record.holderDid}, ${record.credentialIds},
      ${sql.json(record.document as any)}, ${sql.json(record.disclosedClaims as any)}
    )
  `
}

export async function findPresentation(id: string): Promise<PresentationRecord | null> {
  const [row] = await sql`
    SELECT id, holder_did, credential_ids, document, disclosed_claims, created_at
    FROM presentations WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id,
    holderDid: row.holderDid,
    credentialIds: row.credentialIds,
    document: row.document,
    disclosedClaims: row.disclosedClaims,
    createdAt: row.createdAt,
  }
}
