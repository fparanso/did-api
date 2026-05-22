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
    new AppError('INVALID_PROOF', 'BBS+ proof verification failed', 422),
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
}
