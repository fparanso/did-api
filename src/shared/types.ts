// src/shared/types.ts
export type Role = 'subject' | 'issuer' | 'verifier' | 'attester'
export type AuditAction = 'issue' | 'revoke' | 'verify' | 'attest' | 'auth'
export type ResourceStatus = 'active' | 'revoked'

export interface DidRecord {
  id: string
  role: Role
  document: Record<string, unknown>
  publicKey: string           // P-256 JWK as JSON string
  privateKey: string          // AES-GCM encrypted P-256 JWK JSON string
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
  sdJwt: string | null
  mdoc: string | null
  mdocDocType: string | null
  deviceKey: Record<string, unknown> | null
  statusListId: string
  statusListIndex: number | null
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
  requestId: string
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
    memberRole: OrgMemberRole
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
export type OrgInviteRole = Exclude<OrgMemberRole, 'owner'>

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
  role: OrgInviteRole
  token: string
  accepted: boolean
  expiresAt: Date
  createdAt: Date
}
