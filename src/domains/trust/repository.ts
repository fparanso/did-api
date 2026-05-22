// src/domains/trust/repository.ts
import { sql } from '../../shared/db.js'
import type { TrustAttestationRecord } from '../../shared/types.js'

export async function insertAttestation(
  record: Omit<TrustAttestationRecord, 'issuedAt'>
): Promise<void> {
  await sql`
    INSERT INTO trust_attestations (id, attester_did, issuer_did, credential, status, expires_at)
    VALUES (
      ${record.id}, ${record.attesterDid}, ${record.issuerDid},
      ${sql.json(record.credential as any)}, ${record.status}, ${record.expiresAt ?? null}
    )
  `
}

export async function findActiveAttestation(
  issuerDid: string
): Promise<TrustAttestationRecord | null> {
  const [row] = await sql`
    SELECT id, attester_did, issuer_did, credential, status, issued_at, expires_at
    FROM trust_attestations
    WHERE issuer_did = ${issuerDid}
      AND status = 'active'
      AND (expires_at IS NULL OR expires_at > now())
    ORDER BY issued_at DESC LIMIT 1
  `
  if (!row) return null
  return {
    id: row.id,
    attesterDid: row.attesterDid,
    issuerDid: row.issuerDid,
    credential: row.credential,
    status: row.status,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt ?? null,
  }
}

export async function listTrustedIssuers(): Promise<
  { issuerDid: string; attesterDid: string; issuedAt: Date }[]
> {
  return sql`
    SELECT DISTINCT ON (issuer_did)
      issuer_did, attester_did, issued_at
    FROM trust_attestations
    WHERE status = 'active' AND (expires_at IS NULL OR expires_at > now())
    ORDER BY issuer_did, issued_at DESC
  `
}

export async function revokeAttestation(id: string, attesterDid: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE trust_attestations SET status = 'revoked'
    WHERE id = ${id} AND attester_did = ${attesterDid} AND status = 'active'
    RETURNING id
  `
  return !!row
}
