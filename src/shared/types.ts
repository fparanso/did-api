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

export interface UserRecord {
  id: string
  email: string
  passwordHash: string
  name: string
  organizationName: string | null
  did: string
  createdAt: Date
}

export interface UserProfile {
  id: string
  email: string
  name: string
  organizationName: string | null
  did: string
  role: Role
  createdAt: Date
  organizations: Array<{
    id: string
    name: string
    slug: string
    memberRole: 'owner' | 'admin' | 'member'
  }>
}

export interface PasswordResetTokenRecord {
  id: string
  userId: string
  token: string
  expiresAt: Date
  used: boolean
  createdAt: Date
}

export type OrgMemberRole = 'owner' | 'admin' | 'member'

export interface OrgRecord {
  id: string
  name: string
  slug: string
  did: string
  ownerId: string
  createdAt: Date
}

export interface OrgMemberRecord {
  orgId: string
  userId: string
  role: OrgMemberRole
  joinedAt: Date
}

export interface OrgInviteRecord {
  id: string
  orgId: string
  invitedBy: string
  email: string | null
  did: string | null
  role: 'admin' | 'member'
  token: string
  accepted: boolean
  expiresAt: Date
  createdAt: Date
}
