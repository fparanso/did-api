// src/domains/credentials/repository.ts
import { sql } from '../../shared/db.js'
import type { CredentialRecord } from '../../shared/types.js'

export async function insertCredential(
  record: Omit<CredentialRecord, 'issuedAt'>
): Promise<void> {
  await sql`
    INSERT INTO credentials (id, issuer_did, subject_did, type, claims, document, status, expires_at)
    VALUES (
      ${record.id}, ${record.issuerDid}, ${record.subjectDid},
      ${record.type}, ${JSON.stringify(record.claims)},
      ${JSON.stringify(record.document)}, ${record.status}, ${record.expiresAt ?? null}
    )
  `
}

export async function findCredential(id: string): Promise<CredentialRecord | null> {
  const [row] = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at
    FROM credentials WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id,
    issuerDid: row.issuerDid,
    subjectDid: row.subjectDid,
    type: row.type,
    claims: row.claims,
    document: row.document,
    status: row.status,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt ?? null,
  }
}

export async function listCredentialsByIssuer(issuerDid: string): Promise<CredentialRecord[]> {
  const rows = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at
    FROM credentials WHERE issuer_did = ${issuerDid}
    ORDER BY issued_at DESC
  `
  return rows.map((row: any) => ({
    id: row.id,
    issuerDid: row.issuerDid,
    subjectDid: row.subjectDid,
    type: row.type,
    claims: row.claims,
    document: row.document,
    status: row.status,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt ?? null,
  }))
}

export async function revokeCredential(id: string, issuerDid: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE credentials SET status = 'revoked'
    WHERE id = ${id} AND issuer_did = ${issuerDid} AND status = 'active'
    RETURNING id
  `
  return !!row
}
