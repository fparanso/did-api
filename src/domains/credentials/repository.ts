// src/domains/credentials/repository.ts
import { sql } from '../../shared/db.js'
import type { CredentialRecord } from '../../shared/types.js'

function mapRow(row: any): CredentialRecord {
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
    sdJwt: row.sdJwt ?? null,
    mdoc: row.mdoc ?? null,
    mdocDocType: row.mdocDocType ?? null,
    deviceKey: row.deviceKey ?? null,
    statusListId: row.statusListId ?? 'default',
    statusListIndex: row.statusListIndex ?? null,
  }
}

export async function insertCredential(
  record: Omit<CredentialRecord, 'issuedAt'>
): Promise<void> {
  await sql`
    INSERT INTO credentials (
      id, issuer_did, subject_did, type, claims, document, status, expires_at,
      sd_jwt, mdoc, mdoc_doc_type, device_key, status_list_id, status_list_index
    )
    VALUES (
      ${record.id}, ${record.issuerDid}, ${record.subjectDid},
      ${record.type}, ${sql.json(record.claims as any)},
      ${sql.json(record.document as any)}, ${record.status}, ${record.expiresAt ?? null},
      ${record.sdJwt ?? null}, ${record.mdoc ?? null}, ${record.mdocDocType ?? null},
      ${record.deviceKey ? sql.json(record.deviceKey as any) : null},
      ${record.statusListId ?? 'default'}, ${record.statusListIndex ?? null}
    )
  `
}

export async function findCredential(id: string): Promise<CredentialRecord | null> {
  const [row] = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at,
           sd_jwt, mdoc, mdoc_doc_type, device_key, status_list_id, status_list_index
    FROM credentials WHERE id = ${id}
  `
  if (!row) return null
  return mapRow(row)
}

export async function listCredentialsByIssuer(issuerDid: string): Promise<CredentialRecord[]> {
  const rows = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at,
           sd_jwt, mdoc, mdoc_doc_type, device_key, status_list_id, status_list_index
    FROM credentials WHERE issuer_did = ${issuerDid}
    ORDER BY issued_at DESC
  `
  return rows.map((row: any) => mapRow(row))
}

export async function findCredentialsBySubject(subjectDid: string): Promise<CredentialRecord[]> {
  const rows = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at,
           sd_jwt, mdoc, mdoc_doc_type, device_key, status_list_id, status_list_index
    FROM credentials WHERE subject_did = ${subjectDid}
    ORDER BY issued_at DESC
  `
  return rows.map((row: any) => mapRow(row))
}

export async function getAllCredentialsByStatusListId(statusListId: string): Promise<CredentialRecord[]> {
  const rows = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at,
           sd_jwt, mdoc, mdoc_doc_type, device_key, status_list_id, status_list_index
    FROM credentials WHERE status_list_id = ${statusListId}
  `
  return rows.map((row: any) => mapRow(row))
}

export async function getNextStatusIndex(): Promise<number> {
  const [row] = await sql`SELECT nextval('credential_status_idx_seq') AS idx`
  return Number(row.idx)
}

export async function revokeCredential(id: string, issuerDid: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE credentials SET status = 'revoked'
    WHERE id = ${id} AND issuer_did = ${issuerDid} AND status = 'active'
    RETURNING id
  `
  return !!row
}
