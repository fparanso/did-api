// src/shared/errors.ts
export class AppError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number
  ) {
    super(message)
    this.name = 'AppError'
  }
}

export const Errors = {
  DID_NOT_FOUND: (did: string) =>
    new AppError('DID_NOT_FOUND', `DID ${did} not found`, 404),
  CREDENTIAL_NOT_FOUND: (id: string) =>
    new AppError('CREDENTIAL_NOT_FOUND', `Credential ${id} not found`, 404),
  PRESENTATION_NOT_FOUND: (id: string) =>
    new AppError('PRESENTATION_NOT_FOUND', `Presentation ${id} not found`, 404),
  ATTESTATION_NOT_FOUND: (id: string) =>
    new AppError('ATTESTATION_NOT_FOUND', `Attestation ${id} not found`, 404),
  INVALID_PROOF: () =>
    new AppError('INVALID_PROOF', 'Proof verification failed', 422),
  CREDENTIAL_REVOKED: () =>
    new AppError('CREDENTIAL_REVOKED', 'The credential has been revoked', 422),
  ISSUER_NOT_TRUSTED: () =>
    new AppError('ISSUER_NOT_TRUSTED', 'Issuer has no active attestation', 403),
  CHALLENGE_EXPIRED: () =>
    new AppError('CHALLENGE_EXPIRED', 'Nonce expired or already used', 401),
  UNAUTHORIZED_ROLE: () =>
    new AppError('UNAUTHORIZED_ROLE', 'Insufficient role for this action', 403),
  INVALID_DISCLOSURE: () =>
    new AppError('INVALID_DISCLOSURE', 'Requested claims do not exist in the credential', 422),
  INVALID_CONTEXT: (url: string) =>
    new AppError('INVALID_CONTEXT', `Unknown JSON-LD context: ${url}`, 422),
  RATE_LIMITED: () =>
    new AppError('RATE_LIMITED', 'Too many requests', 429),
  FORBIDDEN: () =>
    new AppError('FORBIDDEN', 'Access denied', 403),
  EMAIL_TAKEN: () =>
    new AppError('EMAIL_TAKEN', 'An account with this email already exists', 409),
  INVALID_CREDENTIALS: () =>
    new AppError('INVALID_CREDENTIALS', 'Invalid email or password', 401),
  USER_NOT_FOUND: () =>
    new AppError('USER_NOT_FOUND', 'User not found', 404),
  RESET_TOKEN_INVALID: () =>
    new AppError('RESET_TOKEN_INVALID', 'Reset token not found', 404),
  RESET_TOKEN_USED: () =>
    new AppError('RESET_TOKEN_USED', 'Reset token has already been used', 410),
  RESET_TOKEN_EXPIRED: () =>
    new AppError('RESET_TOKEN_EXPIRED', 'Reset token has expired', 410),
  SLUG_TAKEN: () =>
    new AppError('SLUG_TAKEN', 'Organization slug is already taken', 409),
  ALREADY_MEMBER: () =>
    new AppError('ALREADY_MEMBER', 'User is already a member of this organization', 409),
  INVITE_NOT_FOUND: () =>
    new AppError('INVITE_NOT_FOUND', 'Invite not found', 404),
  INVITE_EXPIRED: () =>
    new AppError('INVITE_EXPIRED', 'Invite has expired', 410),
  INVITE_ALREADY_USED: () =>
    new AppError('INVITE_ALREADY_USED', 'Invite has already been accepted', 409),
  CANNOT_REMOVE_LAST_OWNER: () =>
    new AppError('CANNOT_REMOVE_LAST_OWNER', 'Cannot remove or demote the last owner', 409),
  INSUFFICIENT_ORG_ROLE: () =>
    new AppError('INSUFFICIENT_ORG_ROLE', 'Insufficient organization role for this action', 403),
  ORG_NOT_FOUND: (id: string) =>
    new AppError('ORG_NOT_FOUND', `Organization ${id} not found`, 404),
  INVALID_DPOP: () =>
    new AppError('INVALID_DPOP', 'DPoP proof verification failed', 401),
  INVALID_GRANT: () =>
    new AppError('INVALID_GRANT', 'The provided authorization grant is invalid or expired', 400),
  INVALID_REQUEST: () =>
    new AppError('INVALID_REQUEST', 'The request is missing a required parameter or is otherwise malformed', 400),
  INVALID_CLIENT: () =>
    new AppError('INVALID_CLIENT', 'Client authentication failed', 401),
  UNSUPPORTED_FORMAT: () =>
    new AppError('UNSUPPORTED_FORMAT', 'The requested credential format is not supported in this path', 400),
}
