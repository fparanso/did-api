// src/shared/types.ts
export type Role = 'subject' | 'issuer' | 'verifier' | 'attester'
export type AuditAction = 'issue' | 'revoke' | 'verify' | 'attest' | 'auth'
export type ResourceStatus = 'active' | 'revoked'

export interface DidRecord {
  id: string
  role: Role
  document: Record<string, unknown>
  publicKey: string           // Ed25519 multibase (for DID Auth)
  privateKey: string          // AES-GCM encrypted Ed25519 private key
  blsPublicKey: string | null // BLS12-381 G2 multibase (issuers only)
  blsPrivateKey: string | null // AES-GCM encrypted BLS12-381 (issuers only)
  createdAt: Date
  deactivatedAt: Date | null
}

export interface CredentialRecord {
  id: string
  issuerDid: string
  subjectDid: string
  type: string[]
  claims: Record<string, unknown>
  document: Record<string, unknown>
  status: ResourceStatus
  issuedAt: Date
  expiresAt: Date | null
}

export interface PresentationRecord {
  id: string
  holderDid: string
  credentialIds: string[]
  document: Record<string, unknown>
  disclosedClaims: Record<string, unknown>
  createdAt: Date
}

export interface TrustAttestationRecord {
  id: string
  attesterDid: string
  issuerDid: string
  credential: Record<string, unknown>
  status: ResourceStatus
  issuedAt: Date
  expiresAt: Date | null
}

export interface HonoVariables {
  did: string
  role: Role
}
