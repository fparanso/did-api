// src/shared/openapi.ts

export const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'DID + HAIP REST API',
    version: '2.0.0',
    description: `A production-ready REST API built with **Bun + Hono** that implements the W3C Decentralized Identity (DID) protocol aligned with the **OpenID4VC High Assurance Interoperability Profile 1.0 (HAIP)**. Credentials are issued as **SD-JWT VC** (\`dc+sd-jwt\`) and **ISO 18013-5 mso_mdoc**, enabling privacy-preserving selective disclosure without external cryptographic libraries.

---

## Core Concepts

### Actors and roles
Every participant is assigned one of four roles:

| Role | Responsibility |
|------|----------------|
| **attester** | Trust anchor — vouches for which issuers are allowed to sign credentials |
| **issuer** | Signs SD-JWT VC and mso_mdoc credentials for subjects (requires active trust attestation) |
| **subject** | Holds credentials; derives selective-disclosure presentations via SD-JWT |
| **verifier** | Validates presentations against proof, trust chain, and revocation status |

### Authentication — two paths

**Path A — Email/password (recommended for user-facing apps):**
1. \`POST /v1/auth/signup\` — create account; a \`did:key\` (P-256) is generated automatically and returned
2. \`POST /v1/auth/login\` — exchange email + password for a **JWT Bearer token**
3. Use the token as \`Authorization: Bearer <token>\` on protected endpoints

**Path B — DID challenge–response (cryptographic, for autonomous agents/services):**
1. \`POST /v1/dids\` — create a raw DID keypair (P-256 / ES256) without a user account
2. \`POST /v1/auth/challenge\` — receive a one-time nonce
3. Sign \`"{did}:{nonce}"\` with your **P-256 private key** using ECDSA/SHA-256; encode the DER-encoded signature as **base64**
4. \`POST /v1/auth/verify\` — exchange the signature for a **JWT Bearer token**

Both paths issue the same JWT format and grant the same access to protected endpoints.

### Typical end-to-end flow (email auth + direct credential API)

\`\`\`
1. [attester]  POST /v1/auth/signup              → Create account (role defaults to subject; upgrade via admin)
2. [admin]     POST /v1/admin/users/{id}/role    → Upgrade attester/issuer roles
3. [attester]  POST /v1/auth/login               → Get JWT
4. [attester]  POST /v1/trust/attest             → Grant issuer trust attestation
5. [issuer]    POST /v1/auth/login               → Get JWT
6. [issuer]    POST /v1/credentials/issue        → Issue SD-JWT VC + mso_mdoc to subject
7. [subject]   POST /v1/auth/login               → Get JWT
8. [subject]   POST /v1/presentations/derive     → Derive SD-JWT selective-disclosure VP
9. [verifier]  POST /v1/presentations/verify     → Verify proof + trust chain + revocation
\`\`\`

### OID4VCI — OpenID for Verifiable Credential Issuance

Full authorization-code flow with PKCE, PAR, and DPoP for machine-to-machine issuance:

\`\`\`
1. [client]    POST /oauth/par                               → Pushed Authorization Request (PAR)
2. [client]    GET  /oauth/authorize?request_uri=urn:...    → Authorization redirect (PKCE)
3. [client]    POST /oauth/token  (+ DPoP proof)            → Access token + c_nonce
4. [client]    POST /oauth/nonce                             → Refresh c_nonce
5. [client]    POST /oauth/credentials  (+ key proof JWT)   → Receive sd-jwt or mso_mdoc
\`\`\`

### OID4VP — OpenID for Verifiable Presentations

Verifier-initiated presentation flow using signed JAR request objects and direct_post:

\`\`\`
1. [verifier]  POST /oauth/vp/initiate    → Get request_uri + nonce
2. [wallet]    GET  /oauth/request/{id}  → Fetch signed JAR request object
3. [wallet]    POST /oauth/direct_post   → Submit VP token (SD-JWT with KB-JWT)
4. [verifier]  GET  /oauth/vp-result/{id} → Poll for verified result
\`\`\`

### Privacy model (SD-JWT selective disclosure)
SD-JWT VC uses **salted hashing** to allow a credential holder to reveal only a chosen subset of claims. Each claim is individually salted and hashed; the holder presents only the disclosures they choose to reveal along with a Key Binding JWT (KB-JWT) proving holder binding. The verifier learns only what the subject explicitly discloses.

### Revocation — Token Status List 1.0
Credentials are tracked via a **Token Status List** (draft-ietf-oauth-status-list). Each issuer's credentials share a compact bit-vector bitmap published as a signed JWT at \`GET /v1/credentials/status-lists/{id}\`. Revocation is reflected immediately on the status list.

---

## Global limits
- **Rate limit:** 100 requests / minute per IP (global); 10 requests / minute for \`POST /v1/credentials/issue\`
- **Body size:** 64 KB maximum
- **JWT lifetime:** 15 minutes (email/password login: 2 hours in non-production environments)`,
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Local development server',
    },
  ],
  security: [],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Provide your 15-minute JWT session token received from `/v1/auth/verify` or `/v1/auth/login`.',
      },
      DPoP: {
        type: 'http',
        scheme: 'dpop',
        bearerFormat: 'JWT',
        description: 'DPoP-bound access token (RFC 9449). Requires `DPoP` header containing a proof JWT.',
      },
    },
    schemas: {
      ErrorResponse: {
        type: 'object',
        required: ['error', 'message', 'status'],
        properties: {
          error: {
            type: 'string',
            example: 'VALIDATION_ERROR',
          },
          message: {
            type: 'string',
            example: 'Invalid request body parameter.',
          },
          status: {
            type: 'integer',
            example: 400,
          },
        },
      },
      UserProfile: {
        type: 'object',
        required: ['id', 'email', 'name', 'did', 'role', 'createdAt'],
        properties: {
          id: { type: 'string', format: 'uuid', example: '3fa85f64-5717-4562-b3fc-2c963f66afa6' },
          email: { type: 'string', format: 'email', example: 'alice@example.com' },
          name: { type: 'string', example: 'Alice Smith' },
          organizationName: { type: 'string', nullable: true, example: 'Acme University' },
          did: { type: 'string', example: 'did:key:zDnae...' },
          role: { type: 'string', enum: ['subject', 'issuer', 'verifier', 'attester'], example: 'subject' },
          createdAt: { type: 'string', format: 'date-time' },
          organizations: {
            type: 'array',
            items: {
              type: 'object',
              required: ['id', 'name', 'slug', 'did', 'memberRole'],
              properties: {
                id: { type: 'string', format: 'uuid' },
                name: { type: 'string' },
                slug: { type: 'string' },
                did: { type: 'string' },
                memberRole: { type: 'string', enum: ['member', 'admin', 'owner'] },
              },
            },
          },
        },
      },
      AuthResponse: {
        type: 'object',
        required: ['token', 'user'],
        properties: {
          token: { type: 'string', description: 'JWT Bearer token', example: 'eyJhbGciOi...' },
          user: { $ref: '#/components/schemas/UserProfile' },
        },
      },
      OrgRecord: {
        type: 'object',
        required: ['id', 'name', 'slug', 'did', 'createdAt'],
        properties: {
          id: { type: 'string', format: 'uuid' },
          name: { type: 'string', example: 'Test University' },
          slug: { type: 'string', example: 'test-university' },
          did: { type: 'string', example: 'did:key:zDnae...' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
      OrgMember: {
        type: 'object',
        required: ['userId', 'email', 'name', 'role', 'joinedAt'],
        properties: {
          userId: { type: 'string', format: 'uuid' },
          email: { type: 'string', format: 'email' },
          name: { type: 'string' },
          role: { type: 'string', enum: ['member', 'admin', 'owner'] },
          joinedAt: { type: 'string', format: 'date-time' },
        },
      },
      PublicKeyJwk: {
        type: 'object',
        description: 'P-256 public key in JWK format (RFC 7517)',
        required: ['kty', 'crv', 'x', 'y'],
        properties: {
          kty: { type: 'string', enum: ['EC'], example: 'EC' },
          crv: { type: 'string', enum: ['P-256'], example: 'P-256' },
          x: { type: 'string', description: 'base64url-encoded X coordinate', example: 'f83OJ3D2xF1...' },
          y: { type: 'string', description: 'base64url-encoded Y coordinate', example: 'x_FEzRu9m36...' },
        },
      },
      PrivateKeyJwk: {
        type: 'object',
        description: 'P-256 private key in JWK format — returned ONLY at creation time',
        required: ['kty', 'crv', 'x', 'y', 'd'],
        properties: {
          kty: { type: 'string', enum: ['EC'], example: 'EC' },
          crv: { type: 'string', enum: ['P-256'], example: 'P-256' },
          x: { type: 'string', example: 'f83OJ3D2xF1...' },
          y: { type: 'string', example: 'x_FEzRu9m36...' },
          d: { type: 'string', description: 'base64url-encoded private scalar — store securely', example: 'jpsQnnGQmL...' },
        },
      },
      OID4VCIMetadata: {
        type: 'object',
        description: 'OpenID for Verifiable Credential Issuance metadata (RFC draft-ietf-oauth-par, HAIP 1.0)',
        properties: {
          issuer: { type: 'string', example: 'http://localhost:3000' },
          credential_issuer: { type: 'string', example: 'http://localhost:3000' },
          credential_endpoint: { type: 'string', example: 'http://localhost:3000/oauth/credentials' },
          pushed_authorization_request_endpoint: { type: 'string', example: 'http://localhost:3000/oauth/par' },
          authorization_endpoint: { type: 'string', example: 'http://localhost:3000/oauth/authorize' },
          token_endpoint: { type: 'string', example: 'http://localhost:3000/oauth/token' },
          dpop_signing_alg_values_supported: { type: 'array', items: { type: 'string' }, example: ['ES256'] },
          credential_configurations_supported: { type: 'object' },
        },
      },
    },
  },
  tags: [
    { name: 'Email Auth', description: 'Email/password signup, login, and password reset' },
    { name: 'Users', description: 'User profile management' },
    { name: 'Admin', description: 'Administrative operations (requires X-Admin-Secret header)' },
    { name: 'Organizations', description: 'Organization management — create orgs, manage members, and send invites' },
    { name: 'Authentication', description: 'DID-based challenge–response authentication (P-256 ECDSA / ES256)' },
    { name: 'DID Management', description: 'Create and resolve did:key (P-256) identities' },
    { name: 'Verifiable Credentials', description: 'Issue (SD-JWT VC + mso_mdoc), retrieve, and revoke credentials — direct REST API' },
    { name: 'Verifiable Presentations', description: 'Derive and verify SD-JWT selective-disclosure presentations — direct REST API' },
    { name: 'Trust Registry', description: 'Manage trust attestations between attesters and issuers' },
    { name: 'OID4VCI', description: 'OpenID for Verifiable Credential Issuance — authorization-code flow with PKCE, PAR, and DPoP (HAIP 1.0)' },
    { name: 'OID4VP', description: 'OpenID for Verifiable Presentations — verifier-initiated flow with signed JAR request objects and direct_post (HAIP 1.0)' },
    { name: 'Status List', description: 'Token Status List 1.0 — compact bitmap revocation registry for SD-JWT VC credentials' },
  ],
  paths: {
    '/v1/auth/signup': {
      post: {
        tags: ['Email Auth'],
        summary: 'Sign up with email and password',
        description: `Create a new user account. A \`did:key\` identity (P-256 keypair) is generated automatically and linked to the account — you do not need to call \`POST /v1/dids\` separately.

**Returns:** A JWT Bearer token and the user profile including the generated DID.

**Role:** All new accounts start with role \`subject\`. Use \`POST /v1/admin/users/{id}/role\` to upgrade to \`issuer\`, \`verifier\`, or \`attester\`.

**Constraints:**
- Email must be unique (409 \`EMAIL_TAKEN\` if already registered)
- Password must be ≥ 8 characters
- The P-256 private key JWK for the generated DID is returned **only once** and not stored — save it if you intend to use DID challenge-response auth in parallel`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'password', 'name'],
                properties: {
                  email: { type: 'string', format: 'email', example: 'alice@example.com' },
                  password: { type: 'string', minLength: 8, example: 'password123' },
                  name: { type: 'string', example: 'Alice Smith' },
                  organizationName: { type: 'string', example: 'Acme University', description: 'Optional display name for the user\'s organization affiliation.' },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Account created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/AuthResponse' },
              },
            },
          },
          '400': {
            description: 'Validation error (invalid email, password too short, missing fields)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'Email already registered',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/login': {
      post: {
        tags: ['Email Auth'],
        summary: 'Log in with email and password',
        description: `Exchange email + password credentials for a JWT Bearer token.

**Token lifetime:** 15 minutes in production; 2 hours in non-production environments.

**Security:** Uses Argon2id password hashing (OWASP parameters). Timing-safe comparison prevents email enumeration — both unknown-email and wrong-password return the same \`INVALID_CREDENTIALS\` error.`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'password'],
                properties: {
                  email: { type: 'string', format: 'email', example: 'alice@example.com' },
                  password: { type: 'string', example: 'password123' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Login successful',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Invalid credentials (wrong password or unknown email)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/forgot-password': {
      post: {
        tags: ['Email Auth'],
        summary: 'Request password reset email',
        description: `Triggers a password reset flow. A reset token (valid for **72 hours**) is generated and would be emailed to the user in a production deployment.

**Security:** Always returns \`200\` with the same response shape regardless of whether the email is registered — this prevents email enumeration.

**Development note:** The token is not actually emailed; retrieve it from the database directly for testing.`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email'],
                properties: {
                  email: { type: 'string', format: 'email', example: 'alice@example.com' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Reset email sent (or silently ignored for unknown addresses)',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['message'],
                  properties: { message: { type: 'string', example: 'If that email is registered, a reset link has been sent.' } },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/reset-password': {
      post: {
        tags: ['Email Auth'],
        summary: 'Reset password using token',
        description: `Consume a password reset token and set a new password. The token is a 64-character hex string from the \`forgot-password\` flow.

**One-time use:** The token is atomically consumed on success — re-using it returns \`410 Gone\`.

**Side effect:** All existing sessions for the user are invalidated on successful reset.`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['token', 'newPassword'],
                properties: {
                  token: { type: 'string', minLength: 64, maxLength: 64, example: 'a3f9e2b1...' },
                  newPassword: { type: 'string', minLength: 8, example: 'newPassword1' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Password reset successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['message'],
                  properties: { message: { type: 'string', example: 'Password reset successful.' } },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Token not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '410': {
            description: 'Token already used or expired',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/users/me': {
      get: {
        tags: ['Users'],
        summary: 'Get current user profile',
        description: `Returns the full profile for the currently authenticated user, including their DID, role, and a list of organizations they belong to.

**Authentication:** Requires a valid Bearer JWT (from either \`/v1/auth/login\` or \`/v1/auth/verify\`).`,
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Profile retrieved',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/UserProfile' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      patch: {
        tags: ['Users'],
        summary: 'Update current user profile',
        description: `Update editable fields on the authenticated user's profile. All fields are optional — only send the fields you want to change.

**Editable fields:** \`name\`, \`organizationName\`.

**Non-editable:** \`email\`, \`did\`, \`role\` (use admin endpoint to change role).`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: 'Alice J. Smith' },
                  organizationName: { type: 'string', example: 'MIT' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Profile updated',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/UserProfile' } } },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/admin/users/{id}/role': {
      post: {
        tags: ['Admin'],
        summary: 'Upgrade a user\'s DID role',
        description: `Elevate a user's role to \`issuer\`, \`verifier\`, or \`attester\`. This also updates the underlying \`did:key\` record so the new role is reflected in the JWT on their next login.

**Authentication:** Requires the \`X-Admin-Secret\` header to match the server's \`ADMIN_SECRET\` environment variable. The check is timing-safe.

**Audit:** The role change is written to the audit log with action \`role_upgrade\`.`,
        security: [],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
            description: 'User ID (UUID) to upgrade',
          },
          {
            name: 'X-Admin-Secret',
            in: 'header',
            required: true,
            schema: { type: 'string' },
            description: 'Server admin secret for administrative operations',
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['role'],
                properties: {
                  role: { type: 'string', enum: ['issuer', 'verifier', 'attester'], example: 'issuer' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Role upgraded successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Missing or invalid X-Admin-Secret',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'User not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations': {
      post: {
        tags: ['Organizations'],
        summary: 'Create an organization',
        description: `Create a new organization with its own \`did:key\` (P-256) identity. The caller becomes the organization **owner**.

**DID role:** Specify the role the organization will play (\`issuer\`, \`verifier\`, etc.) — this determines what operations the org DID can perform.

**Slug:** Auto-generated from the name (lowercased, spaces → hyphens, diacritics stripped). Must be unique — \`409 SLUG_TAKEN\` if already registered.

**Authentication:** Requires a valid Bearer JWT.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name', 'role'],
                properties: {
                  name: { type: 'string', example: 'Test University' },
                  role: { type: 'string', enum: ['issuer', 'verifier', 'attester', 'subject'], example: 'issuer' },
                  slug: { type: 'string', description: 'Custom slug (optional, auto-generated if omitted)', example: 'test-university' },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Organization created',
            content: {
              'application/json': {
                schema: {
                  allOf: [
                    { $ref: '#/components/schemas/OrgRecord' },
                    {
                      type: 'object',
                      required: ['memberRole'],
                      properties: { memberRole: { type: 'string', enum: ['owner'], example: 'owner' } },
                    },
                  ],
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'Slug already taken',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations/{id}': {
      get: {
        tags: ['Organizations'],
        summary: 'Get organization details',
        description: `Returns the organization record. Caller must be a member of the organization (any role).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
        ],
        responses: {
          '200': {
            description: 'Organization details',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OrgRecord' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller is not a member of this organization',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Organization not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      delete: {
        tags: ['Organizations'],
        summary: 'Delete organization',
        description: `Permanently deletes the organization, deactivates its DID, and removes all members and pending invites. **This action is irreversible.**

**Authorization:** Caller must be an **owner** of the organization.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
        ],
        responses: {
          '200': {
            description: 'Organization deleted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller is not an owner',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Organization not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations/{id}/members': {
      get: {
        tags: ['Organizations'],
        summary: 'List organization members',
        description: `Returns all current members of the organization with their roles and join dates.

**Authorization:** Caller must be a member of the organization (any role).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
        ],
        responses: {
          '200': {
            description: 'Members list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['members'],
                  properties: {
                    members: { type: 'array', items: { $ref: '#/components/schemas/OrgMember' } },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller is not a member',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Organization not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations/{id}/members/{userId}': {
      patch: {
        tags: ['Organizations'],
        summary: 'Update member role',
        description: `Change the role of an existing organization member.

**Role hierarchy:** \`member < admin < owner\`

**Authorization rules:**
- Caller must be **admin** or **owner**
- Admins can promote members to \`admin\` but cannot assign \`owner\`
- Owners can change anyone except themselves
- Cannot demote the last owner (returns \`409 CANNOT_REMOVE_LAST_OWNER\`)`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
          { name: 'userId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Target member user ID' },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['role'],
                properties: {
                  role: { type: 'string', enum: ['member', 'admin', 'owner'], example: 'admin' },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Role updated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Insufficient org role',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'Cannot remove last owner',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      delete: {
        tags: ['Organizations'],
        summary: 'Remove member from organization',
        description: `Remove a user from the organization.

**Self-removal:** Any member can remove themselves (leave the org).

**Removing others:** Requires **admin** or **owner** role. Admins cannot remove owners.

**Last owner protection:** Cannot remove the last owner — returns \`409 CANNOT_REMOVE_LAST_OWNER\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
          { name: 'userId', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Target member user ID' },
        ],
        responses: {
          '200': {
            description: 'Member removed',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Insufficient org role',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'Cannot remove last owner',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations/{id}/invites': {
      post: {
        tags: ['Organizations'],
        summary: 'Invite a user to the organization',
        description: `Invite someone to join the organization by email address.

**If the email matches an existing user:** They are added directly as a member. Response includes \`userId\` and \`memberRole\`.

**If the email is unknown:** A pending invite is created. Response includes a 64-character \`inviteToken\` (valid 72 hours) to share with the invitee. They must sign up and call \`POST /v1/organizations/invites/{token}/accept\`.

**Authorization:** Caller must be **admin** or **owner** of the organization.

**Duplicate guard:** Inviting a user who is already a member returns \`409 ALREADY_MEMBER\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' }, description: 'Organization ID' },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['email', 'role'],
                properties: {
                  email: { type: 'string', format: 'email', example: 'newmember@example.com' },
                  role: { type: 'string', enum: ['member', 'admin'], example: 'member' },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Invite created or member added directly',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    userId: { type: 'string', format: 'uuid', description: 'Set when the invitee is an existing user added directly' },
                    memberRole: { type: 'string', enum: ['member', 'admin'], description: 'Set when the invitee is an existing user' },
                    inviteToken: { type: 'string', minLength: 64, maxLength: 64, description: 'Set when the invitee email is unknown; share with the recipient' },
                    expiresAt: { type: 'string', format: 'date-time', description: 'Expiry of the invite token' },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller is not an admin or owner',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'User is already a member',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/organizations/invites/{token}/accept': {
      post: {
        tags: ['Organizations'],
        summary: 'Accept an organization invite',
        description: `Accept a pending organization invite using the token received from the inviter.

**Email enforcement:** The invite is scoped to the email address it was sent to. If the authenticated user's email does not match the invite's target email, the request is rejected with \`403 FORBIDDEN\` (prevents BOLA attacks).

**One-time use:** The token is marked as accepted on success. Re-using it returns \`409 INVITE_ALREADY_USED\`.

**Expiry:** Tokens are valid for 72 hours from creation.

**Authentication:** Caller must be authenticated (Bearer JWT).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: 'token', in: 'path', required: true, schema: { type: 'string', minLength: 64, maxLength: 64 }, description: '64-character hex invite token' },
        ],
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: { type: 'object' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Invite accepted — user is now a member',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Invite email does not match authenticated user email',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Invite token not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '409': {
            description: 'Invite already used or user is already a member',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '410': {
            description: 'Invite token expired',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/challenge': {
      post: {
        tags: ['Authentication'],
        summary: 'Request authentication challenge',
        description: `**Step 1 of 2 — DID-based authentication (P-256 ECDSA).**

Submit your \`did:key\` identifier to receive a one-time challenge nonce. This is the first step of the challenge–response authentication flow.

**How it works:**
1. Call this endpoint with your DID.
2. The server generates a short-lived nonce (TTL ~5 minutes) and stores a \`challengeId\` ↔ nonce pair.
3. Concatenate \`did + ":" + nonce\` (UTF-8), sign the bytes with your **P-256 private key** using **ECDSA/SHA-256** via \`crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, message)\`.
4. base64-encode the resulting **DER-encoded** signature bytes.
5. Pass \`did\`, \`challengeId\`, and the base64 signature to \`POST /v1/auth/verify\` to receive a JWT.

**Prerequisites:** The DID must already exist (created via \`POST /v1/dids\`) and must not be deactivated.

**Rate considerations:** Each call creates a new challenge entry. Unused challenges expire automatically — you do not need to clean them up.`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['did'],
                properties: {
                  did: {
                    type: 'string',
                    description: 'The did:key (P-256) identifier of the authenticating actor.',
                    example: 'did:key:zDnaeWJjH...',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Challenge created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['challengeId', 'nonce'],
                  properties: {
                    challengeId: {
                      type: 'string',
                      format: 'uuid',
                      example: 'a58b9c8f-ddec-44a5-a3b5-732346dac1dd',
                    },
                    nonce: {
                      type: 'string',
                      description: 'Random hex nonce to be signed',
                      example: 'd9b7f5c2a1e8304b...',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid input',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'DID not found or deactivated',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/auth/verify': {
      post: {
        tags: ['Authentication'],
        summary: 'Verify challenge signature',
        description: `**Step 2 of 2 — DID-based authentication (P-256 ECDSA).**

Exchange the signed challenge nonce for a short-lived JWT session token. This token must be included as a \`Bearer\` header on every protected endpoint.

**How to sign the nonce (ES256 / P-256):**
\`\`\`js
const message = new TextEncoder().encode(\`\${did}:\${nonce}\`)
const sigDer = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message)
const signature = Buffer.from(sigDer).toString('base64')
\`\`\`

**Token details:**
- Format: JWT (HS256)
- Lifetime: **15 minutes** — refresh by repeating the challenge flow
- Payload contains: \`did\`, \`role\`, \`exp\`

**Error cases:**
- \`401\` if the signature is invalid, the challenge has expired, or the challengeId is unknown
- \`400\` if \`challengeId\` is not a valid UUID or any required field is missing`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['did', 'challengeId', 'signature'],
                properties: {
                  did: {
                    type: 'string',
                    example: 'did:key:zDnaeWJjH...',
                  },
                  challengeId: {
                    type: 'string',
                    format: 'uuid',
                    example: 'a58b9c8f-ddec-44a5-a3b5-732346dac1dd',
                  },
                  signature: {
                    type: 'string',
                    description: 'base64-encoded DER-encoded ECDSA (P-256/SHA-256) signature of UTF-8(did + ":" + nonce)',
                    example: 'MEYCIQDx...',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Verification successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['token'],
                  properties: {
                    token: {
                      type: 'string',
                      description: 'JWT Session Token',
                      example: 'eyJhbGciOi...',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Challenge expired or signature verification failed',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/dids': {
      post: {
        tags: ['DID Management'],
        summary: 'Create a new DID',
        description: `Generate a new \`did:key\` identity with a **P-256 (secp256r1) keypair** using ES256. This is the entry point for every actor in the system — you must create a DID before you can authenticate.

**HAIP alignment:** P-256 keys are aligned with HAIP 1.0 which mandates ES256 as the signing algorithm for all credential and authentication operations.

**Roles and their capabilities:**

| Role | Can do |
|------|--------|
| \`subject\` | Hold credentials, derive SD-JWT selective-disclosure presentations |
| \`issuer\` | Issue SD-JWT VC and mso_mdoc credentials (requires trust attestation) |
| \`verifier\` | Verify Verifiable Presentations via SD-JWT or OID4VP |
| \`attester\` | Grant/revoke trust attestations to issuers |

**Critical — private key handling:**
The \`privateKey\` field is a **P-256 JWK object** returned **only once**, at creation time. The server does **not** store the private key. If you lose it, the DID cannot be authenticated and it cannot be recovered.

**DID document format:** Multikey type with \`publicKeyJwk\` (P-256 JWK), following W3C DID Core.`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['role'],
                properties: {
                  role: {
                    type: 'string',
                    enum: ['subject', 'issuer', 'verifier', 'attester'],
                    example: 'subject',
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'DID generated successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['did', 'document', 'privateKey'],
                  properties: {
                    did: {
                      type: 'string',
                      description: 'The did:key identifier (P-256 multicodec, base58btc)',
                      example: 'did:key:zDnaeWJjH...',
                    },
                    document: {
                      type: 'object',
                      description: 'The W3C DID document with P-256 Multikey verification method.',
                    },
                    privateKey: {
                      $ref: '#/components/schemas/PrivateKeyJwk',
                    },
                    role: {
                      type: 'string',
                      example: 'subject',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/dids/me': {
      get: {
        tags: ['DID Management'],
        summary: 'Get calling actor\'s DID',
        description: `Returns the DID identifier and the full W3C DID document for the **currently authenticated caller**, as derived from the JWT Bearer token.

Use this endpoint to:
- Confirm which identity the current JWT belongs to
- Retrieve your own DID document (contains your P-256 public key, verification methods, and service endpoints)
- Verify your role before attempting role-restricted operations

**Authentication:** Requires a valid \`Bearer\` JWT from \`POST /v1/auth/verify\` or \`POST /v1/auth/login\`.`,
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Successful retrieval',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['did', 'document'],
                  properties: {
                    did: { type: 'string', example: 'did:key:zDnaeWJjH...' },
                    document: { type: 'object' },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/dids/{did}': {
      get: {
        tags: ['DID Management'],
        summary: 'Resolve DID document',
        description: `Public endpoint. Resolves the W3C DID document for any **active** DID registered with this server.

**Common use cases:**
- An issuer resolves a subject's DID to retrieve their P-256 public key before issuing a credential
- A verifier resolves an issuer's DID to inspect their verification methods
- Any party performs discovery without needing authentication

**Deactivated DIDs:** Returns \`404\`. Once a DID is deactivated via \`DELETE /v1/dids/{did}\`, it cannot be resolved.

**DID document structure** follows the [W3C DID Core spec](https://www.w3.org/TR/did-core/) and includes \`verificationMethod\` (Multikey type with \`publicKeyJwk\`), \`authentication\`, and \`assertionMethod\` entries derived from the P-256 public key.`,
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The target did:key identifier.',
            example: 'did:key:zDnaeWJjH...',
          },
        ],
        responses: {
          '200': {
            description: 'Resolved DID document',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['document'],
                  properties: { document: { type: 'object' } },
                },
              },
            },
          },
          '404': {
            description: 'DID not found or deactivated',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      delete: {
        tags: ['DID Management'],
        summary: 'Deactivate DID',
        description: `Permanently deactivates a DID. **This action is irreversible.**

**Authorization rules:**
- You can only deactivate your **own** DID — the path \`{did}\` must match the DID embedded in your JWT
- Attempting to deactivate another actor's DID returns \`403 Forbidden\`

**Downstream effects of deactivation:**
- The DID can no longer be resolved (returns \`404\`)
- The DID can no longer authenticate (challenge requests will fail)
- Credentials issued to or by this DID remain in storage but the DID document is gone, so they cannot be re-verified against the issuer's public key
- Any active trust attestation for this DID becomes effectively unreachable

**Authentication:** Requires a valid \`Bearer\` JWT from \`POST /v1/auth/verify\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The DID to deactivate.',
          },
        ],
        responses: {
          '200': {
            description: 'Deactivation successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller does not own this DID)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'DID not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials': {
      get: {
        tags: ['Verifiable Credentials'],
        summary: 'List issued credentials',
        description: `Returns all Verifiable Credentials that the authenticated **issuer** has signed and issued.

**Access control:** Requires role \`issuer\`. Subjects and verifiers cannot list credentials from this endpoint — a subject retrieves their own credential via \`GET /v1/credentials/{id}\` after receiving the credential ID out-of-band from the issuer.

**Response shape:** An array of full credential records including status (\`active\`, \`revoked\`, \`expired\`), subject DID, credential type, SD-JWT, mso_mdoc, and Token Status List position.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`issuer\`.`,
        security: [{ BearerAuth: [] }],
        responses: {
          '200': {
            description: 'Credentials list retrieved',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['credentials'],
                  properties: {
                    credentials: { type: 'array', items: { type: 'object' } },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller role is not issuer)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials/issue': {
      post: {
        tags: ['Verifiable Credentials'],
        summary: 'Issue a new Verifiable Credential',
        description: `Signs and persists a new **SD-JWT VC** (\`dc+sd-jwt\`) **and** a corresponding **mso_mdoc** (ISO 18013-5) for a given subject.

**Prerequisites before calling this endpoint:**
1. Caller must have the \`issuer\` role
2. The calling issuer DID must have an **active trust attestation** in the trust registry (granted via \`POST /v1/trust/attest\`). Without attestation, issuance is rejected with \`403 ISSUER_NOT_TRUSTED\`.
3. The \`subjectDid\` must be an existing, active DID registered with this server.

**Credential formats produced:**
- **SD-JWT VC** (\`dc+sd-jwt\`): compact JWT + per-claim salted disclosures, signed with issuer P-256 key (ES256). An ephemeral holder P-256 key is generated; the public key is embedded in the \`cnf.jwk\` claim for holder binding.
- **mso_mdoc** (ISO 18013-5): CBOR-encoded Mobile Security Object, signed with COSE_Sign1 (ES256). Returned as base64url-encoded CBOR.

**Revocation:** Each credential is assigned a position in the issuer's **Token Status List** (draft-ietf-oauth-status-list). The status list is published at \`GET /v1/credentials/status-lists/{id}\`.

**Claim design tips:**
- Keep claims atomic (one fact per key): \`{"degree": "BSc", "gpa": "3.9"}\`
- Each top-level key becomes a separately disclosable SD-JWT claim

**Rate limit:** 10 requests per minute per issuer.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`issuer\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['subjectDid', 'credentialType', 'claims'],
                properties: {
                  subjectDid: {
                    type: 'string',
                    description: 'The recipient subject DID.',
                    example: 'did:key:zDnaeWJjH...',
                  },
                  credentialType: {
                    type: 'array',
                    items: { type: 'string' },
                    minItems: 1,
                    example: ['UniversityDegreeCredential'],
                  },
                  claims: {
                    type: 'object',
                    description: 'Subject attributes to sign as selective disclosures.',
                    example: { name: 'Alice Smith', degree: 'Bachelor of Science', gpa: '3.9' },
                  },
                  expiresAt: {
                    type: 'string',
                    format: 'date-time',
                    description: 'ISO-8601 expiration timestamp.',
                    example: '2030-12-31T23:59:59Z',
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Credential issued successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['id', 'sdJwt', 'mdoc'],
                  properties: {
                    id: { type: 'string', description: 'Credential ID (URN UUID)', example: 'urn:uuid:7179010f-6240-424a-ba92-a16912384aee' },
                    sdJwt: { type: 'string', description: 'SD-JWT VC compact serialization (issuerJwt~disc1~disc2~...~)', example: 'eyJ...~disc1~disc2~' },
                    mdoc: { type: 'string', description: 'mso_mdoc CBOR encoded as base64url', example: 'omdkb2NUeXBl...' },
                    holderKey: { $ref: '#/components/schemas/PrivateKeyJwk', description: 'Ephemeral holder P-256 key JWK for KB-JWT signing — store securely' },
                    proof: {
                      type: 'object',
                      description: 'Legacy DataIntegrityProof envelope for backwards compatibility',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller role is not issuer or issuer lacks active attestation — ISSUER_NOT_TRUSTED)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials/{id}': {
      get: {
        tags: ['Verifiable Credentials'],
        summary: 'Get credential details',
        description: `Retrieves the full Verifiable Credential record by its ID, including the SD-JWT, mso_mdoc, credential type, all claims, issuance date, and current status.

**Access control:** Only the **issuer** who created the credential or the **subject** it was issued to can fetch it. Any other caller receives \`403 Forbidden\`.

**Credential ID format:** URN UUID — e.g. \`urn:uuid:7179010f-6240-424a-ba92-a16912384aee\`. The ID is returned in the response body of \`POST /v1/credentials/issue\` and should be communicated out-of-band to the subject (e.g. via a secure channel or QR code).

**Authentication:** Requires a valid \`Bearer\` JWT (issuer or subject role).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The credential ID (URN/UUID).',
            example: 'urn:uuid:7179010f-6240-424a-ba92-a16912384aee',
          },
        ],
        responses: {
          '200': {
            description: 'Credential record retrieved',
            content: { 'application/json': { schema: { type: 'object' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller is neither issuer nor subject)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Credential not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials/{id}/revoke': {
      post: {
        tags: ['Verifiable Credentials'],
        summary: 'Revoke credential',
        description: `Marks a Verifiable Credential as **revoked**. The revocation is reflected immediately in the **Token Status List** — verifiers polling \`GET /v1/credentials/status-lists/{id}\` will see the bit flipped.

**Access control:** Only the **issuer** who originally signed the credential can revoke it.

**Effect on existing presentations:** Previously derived SD-JWT presentations are not automatically invalidated in storage, but when a verifier calls \`POST /v1/presentations/verify\`, the verification result will include \`"credentialStatus": "revoked"\` and \`"valid": false\`.

**Irreversibility:** Revocation cannot be undone through the API. If you need to re-issue, create a new credential.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`issuer\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The credential ID.',
          },
        ],
        responses: {
          '200': {
            description: 'Credential successfully revoked',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller is not the issuer)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Credential not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials/{id}/status': {
      get: {
        tags: ['Verifiable Credentials'],
        summary: 'Check credential status',
        description: `**Public endpoint — no authentication required.**

Returns the current lifecycle status of a Verifiable Credential. Intended to be polled by verifiers or relying parties before accepting a presentation.

**Possible status values:**

| Status | Meaning |
|--------|---------|
| \`active\` | Credential is valid and has not expired |
| \`revoked\` | Explicitly revoked by the issuer (also reflected in Token Status List) |
| \`expired\` | Past the \`expiresAt\` date set at issuance |
| \`not_found\` | No credential with this ID exists |

**Tip for verifiers:** Call this endpoint before (or alongside) \`POST /v1/presentations/verify\` to short-circuit verification on credentials that are already known to be revoked or expired.`,
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The credential ID.',
          },
        ],
        responses: {
          '200': {
            description: 'Credential status retrieved',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['status'],
                  properties: {
                    status: { type: 'string', enum: ['active', 'revoked', 'expired', 'not_found'], example: 'active' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/v1/presentations/derive': {
      post: {
        tags: ['Verifiable Presentations'],
        summary: 'Derive SD-JWT selective-disclosure presentation',
        description: `Creates a **Verifiable Presentation (VP)** using **SD-JWT selective disclosure** — revealing only the specified subset of claims from an SD-JWT VC, while keeping all other claims hidden.

**How SD-JWT selective disclosure works:**
1. The issued SD-JWT contains salted disclosures for each claim, hashed into an \`_sd\` array in the JWT payload.
2. This endpoint selects only the requested \`revealedClaims\` disclosures from the stored SD-JWT.
3. Returns a partial SD-JWT (\`issuerJwt~disc1~disc2~\`) — the verifier can reconstruct only the disclosed claims.

**Note on Key Binding JWT (KB-JWT):** In the direct REST API flow, KB-JWT is not appended here. For a fully HAIP-compliant presentation with holder binding, use the **OID4VP flow** (\`POST /oauth/vp/initiate\`) which requires the wallet to sign a KB-JWT with the holder key.

**Prerequisites:**
- Caller must own the credential (be its \`subjectDid\`)
- The underlying credential must have status \`active\` — revoked or expired credentials return \`422\`

**Access control:** Requires role \`subject\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['credentialId', 'revealedClaims'],
                properties: {
                  credentialId: { type: 'string', example: 'urn:uuid:7179010f-6240-424a-ba92-a16912384aee' },
                  revealedClaims: {
                    type: 'array',
                    items: { type: 'string' },
                    minItems: 1,
                    example: ['name', 'degree'],
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Presentation derived successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  description: 'The derived partial SD-JWT presentation (issuerJwt~disc1~disc2~).',
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller role is not subject or caller does not own the credential)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '422': {
            description: 'Unprocessable Entity (credential is revoked — CREDENTIAL_REVOKED, or expired)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/presentations/verify': {
      post: {
        tags: ['Verifiable Presentations'],
        summary: 'Verify SD-JWT Verifiable Presentation',
        description: `The end-to-end verification endpoint for verifiers. Accepts an SD-JWT VP and runs a **multi-step verification pipeline**:

1. **SD-JWT signature verification** — validates the issuer ES256 (P-256/SHA-256) signature on the JWT header.payload portion
2. **Disclosure hash verification** — for each presented disclosure, re-computes SHA-256(salt + claim) and confirms it matches an \`_sd\` entry in the JWT
3. **Trust chain check** — confirms the credential's issuer has an active attestation in the trust registry
4. **Revocation check** — confirms the underlying credential has not been revoked or expired (via Token Status List)

**Response fields explained:**

| Field | Description |
|-------|-------------|
| \`valid\` | \`true\` only if ALL four checks above pass |
| \`disclosedClaims\` | The subset of claims the subject chose to reveal |
| \`issuerTrusted\` | Whether the issuer DID is in the active trust registry |
| \`credentialStatus\` | \`active\`, \`revoked\`, or \`expired\` |

**Important:** A \`200\` response does not mean the credential is valid — always check the \`valid\` field.

**Access control:** Requires role \`verifier\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['presentation'],
                properties: {
                  presentation: {
                    type: 'object',
                    description: 'The full Verifiable Presentation object (stored by ID or inline).',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Verification evaluation complete',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['valid', 'disclosedClaims', 'issuerTrusted', 'credentialStatus'],
                  properties: {
                    valid: { type: 'boolean', example: true },
                    disclosedClaims: {
                      type: 'object',
                      description: 'The subset of claims disclosed in the presentation.',
                      example: { name: 'Alice Smith', degree: 'Bachelor of Science' },
                    },
                    issuerTrusted: { type: 'boolean', example: true },
                    credentialStatus: { type: 'string', example: 'active' },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller role is not verifier)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/presentations/{id}': {
      get: {
        tags: ['Verifiable Presentations'],
        summary: 'Get presentation details',
        description: `Retrieves a previously derived SD-JWT Verifiable Presentation by its ID. Useful for subjects to review past presentations or re-share a VP with a new verifier without re-deriving it.

**Access control:** Only the **subject** who derived the presentation can fetch it.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`subject\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The presentation ID.',
          },
        ],
        responses: {
          '200': {
            description: 'Presentation retrieved successfully',
            content: { 'application/json': { schema: { type: 'object' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller is not subject)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Presentation not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/trust/issuers': {
      get: {
        tags: ['Trust Registry'],
        summary: 'List trusted issuers',
        description: `**Public endpoint — no authentication required.**

Returns the DIDs of all issuers currently **active in the trust registry** — i.e., issuers that have a non-expired, non-revoked attestation granted by an \`attester\`.

**Use cases:**
- A verifier pre-fetches this list to build a local trusted-issuer allowlist before processing a batch of presentations
- A subject verifies their issuer is trusted before requesting a credential issuance
- An auditor inspects the current trust landscape

**Note:** Only \`active\` attestations appear in this list. Expired or revoked attestations are excluded automatically.`,
        responses: {
          '200': {
            description: 'List of trusted issuers',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['issuers'],
                  properties: {
                    issuers: { type: 'array', items: { type: 'string' }, example: ['did:key:zDnaeWJjH...'] },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/v1/trust/issuers/{did}': {
      get: {
        tags: ['Trust Registry'],
        summary: 'Check if issuer is trusted',
        description: `**Public endpoint — no authentication required.**

Performs a point-in-time trust lookup for a specific issuer DID. Returns \`{"trusted": true}\` only if the issuer has at least one **active, non-expired** attestation in the registry.

**Note:** The \`POST /v1/presentations/verify\` endpoint already performs this check internally. Only call this endpoint separately if you need a standalone trust check.`,
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The issuer DID to check.',
          },
        ],
        responses: {
          '200': {
            description: 'Trust evaluation result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['trusted'],
                  properties: { trusted: { type: 'boolean', example: true } },
                },
              },
            },
          },
        },
      },
    },
    '/v1/trust/attest': {
      post: {
        tags: ['Trust Registry'],
        summary: 'Attest an issuer',
        description: `Grants a trust attestation to an issuer DID, adding it to the **trust registry**. Until attested, an issuer cannot create credentials — the \`POST /v1/credentials/issue\` endpoint will reject them with \`403 ISSUER_NOT_TRUSTED\`.

**The trust model:**
This API uses a **delegated trust** model. Attesters act as trust anchors (similar to a Certificate Authority). They vouch for which issuers are allowed to sign credentials. Verifiers then check this registry when validating presentations.

**Attestation lifecycle:**
- An attestation is active from creation until its \`expiresAt\` (if set) or until explicitly revoked via \`POST /v1/trust/attest/{id}/revoke\`
- An issuer DID can hold multiple simultaneous attestations from different attesters
- If all attestations for an issuer expire or are revoked, the issuer loses the ability to issue new credentials

**Access control:** Requires role \`attester\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['issuerDid'],
                properties: {
                  issuerDid: { type: 'string', example: 'did:key:zDnaeWJjH...' },
                  expiresAt: { type: 'string', format: 'date-time', description: 'Optional expiration timestamp.', example: '2030-12-31T23:59:59Z' },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Attestation granted successfully',
            content: { 'application/json': { schema: { type: 'object', description: 'The attestation record.' } } },
          },
          '400': {
            description: 'Validation error',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller role is not attester)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/trust/attest/{id}/revoke': {
      post: {
        tags: ['Trust Registry'],
        summary: 'Revoke attestation',
        description: `Revokes an active trust attestation by its ID. Once revoked, the attested issuer loses its trusted status **immediately** — any subsequent \`POST /v1/presentations/verify\` calls for credentials issued by that DID will return \`"issuerTrusted": false\`.

**Access control:** Only the **attester** who granted the original attestation can revoke it.

**Downstream effects:**
- The issuer DID is removed from the active trusted-issuer list
- The issuer can no longer call \`POST /v1/credentials/issue\` (blocked with \`403\`)
- Existing credentials already issued are not deleted, but they will fail trust verification
- The attestation ID is permanent and cannot be re-activated; a new attestation via \`POST /v1/trust/attest\` is required to reinstate trust

**Authentication:** Requires a valid \`Bearer\` JWT with role \`attester\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'The attestation ID.',
          },
        ],
        responses: {
          '200': {
            description: 'Attestation revoked successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['success'],
                  properties: { success: { type: 'boolean', example: true } },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Forbidden (caller is not an attester)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Attestation not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/v1/credentials/status-lists/{id}': {
      get: {
        tags: ['Status List'],
        summary: 'Get Token Status List for an issuer',
        description: `**Public endpoint — no authentication required.**

Returns a **Token Status List 1.0** JWT (draft-ietf-oauth-status-list) for the specified status list ID. The JWT contains a compressed bit-vector bitmap where each bit position corresponds to a credential issued by that issuer.

**Response format:** \`application/statuslist+jwt\` — a signed JWT with:
- \`typ: "statuslist+jwt"\`
- \`status_list.bits: 1\` (1-bit per credential, 0 = valid, 1 = revoked)
- \`status_list.lst\`: base64url-encoded DEFLATE-compressed bitset
- Signed with the issuer's P-256 key (ES256)

**How verifiers use this:**
1. Fetch the status list JWT using the \`statusListUri\` embedded in the credential's \`credentialStatus\` field
2. Verify the JWT signature against the issuer's public key (from DID document)
3. Decompress the bitset and check the bit at \`statusListIndex\`

**Caching:** The status list may be cached by verifiers. Fresh revocations are reflected immediately on the server.`,
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
            description: 'Status list ID (embedded in credential credentialStatus.statusListCredential)',
          },
        ],
        responses: {
          '200': {
            description: 'Token Status List JWT',
            content: {
              'application/statuslist+jwt': {
                schema: {
                  type: 'string',
                  description: 'Compact JWT serialization of the Token Status List',
                  example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand...',
                },
              },
            },
          },
          '404': {
            description: 'Status list not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/.well-known/openid-credential-issuer': {
      get: {
        tags: ['OID4VCI'],
        summary: 'OID4VCI Issuer Metadata',
        description: `**Public endpoint — no authentication required.**

Returns the OpenID for Verifiable Credential Issuance (OID4VCI) issuer metadata document as defined in the OID4VCI specification and required by HAIP 1.0.

**Clients use this endpoint to discover:**
- Credential configurations supported (SD-JWT VC and mso_mdoc formats)
- Authorization endpoints (PAR, authorize, token)
- Credential endpoint URL
- DPoP signing algorithms supported (\`ES256\`)
- Proof types supported (\`jwt\` with \`openid4vci-proof+jwt\` typ)

**Response format:** \`application/json\``,
        responses: {
          '200': {
            description: 'OID4VCI issuer metadata',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/OID4VCIMetadata' },
              },
            },
          },
        },
      },
    },
    '/oauth/par': {
      post: {
        tags: ['OID4VCI'],
        summary: 'Pushed Authorization Request (PAR)',
        description: `**Step 1 of OID4VCI authorization-code flow.**

Implements RFC 9126 Pushed Authorization Request. The client pushes authorization parameters to the server and receives a \`request_uri\` to use in the subsequent \`GET /oauth/authorize\` redirect.

**PKCE:** Required. Clients must generate a \`code_verifier\` (43-128 random chars), compute \`code_challenge = BASE64URL(SHA-256(code_verifier))\`, and send \`code_challenge_method=S256\`.

**Required parameters:**
- \`response_type=code\`
- \`client_id\`: The issuer DID (did:key)
- \`redirect_uri\`: Client callback URI
- \`code_challenge\` + \`code_challenge_method=S256\`
- \`authorization_details\`: JSON array specifying requested credential types

**Returns:** A \`request_uri\` (\`urn:ietf:params:oauth:request_uri:...\`) valid for 90 seconds.`,
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': {
              schema: {
                type: 'object',
                required: ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method'],
                properties: {
                  response_type: { type: 'string', enum: ['code'], example: 'code' },
                  client_id: { type: 'string', description: 'The client DID (did:key)', example: 'did:key:zDnaeWJjH...' },
                  redirect_uri: { type: 'string', format: 'uri', example: 'https://wallet.example.com/callback' },
                  code_challenge: { type: 'string', description: 'BASE64URL(SHA-256(code_verifier))', example: 'E9Melhoa2O...' },
                  code_challenge_method: { type: 'string', enum: ['S256'], example: 'S256' },
                  authorization_details: {
                    type: 'string',
                    description: 'JSON-encoded array of credential request objects',
                    example: '[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]',
                  },
                  scope: { type: 'string', example: 'openid' },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'PAR accepted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['request_uri', 'expires_in'],
                  properties: {
                    request_uri: { type: 'string', example: 'urn:ietf:params:oauth:request_uri:abc123' },
                    expires_in: { type: 'integer', example: 90 },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid request (missing or malformed parameters)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/authorize': {
      get: {
        tags: ['OID4VCI'],
        summary: 'Authorization endpoint (PKCE)',
        description: `**Step 2 of OID4VCI authorization-code flow.**

The client redirects the user/wallet to this endpoint using the \`request_uri\` returned by \`POST /oauth/par\`.

**Flow:**
1. Server retrieves the PAR request using \`request_uri\`
2. Server issues an authorization code (valid 5 minutes)
3. Server redirects to \`redirect_uri?code=...&state=...\`

**PKCE:** The \`code_verifier\` must be provided at token exchange (\`POST /oauth/token\`) to prove possession.

**Authentication:** The DID must be resolvable. No Bearer token required here — the authorization code flow is self-contained.`,
        parameters: [
          {
            name: 'request_uri',
            in: 'query',
            required: true,
            schema: { type: 'string' },
            description: 'The request_uri returned by POST /oauth/par',
            example: 'urn:ietf:params:oauth:request_uri:abc123',
          },
          {
            name: 'client_id',
            in: 'query',
            required: true,
            schema: { type: 'string' },
            description: 'The client DID (must match the PAR request)',
            example: 'did:key:zDnaeWJjH...',
          },
        ],
        responses: {
          '302': {
            description: 'Redirect to redirect_uri with authorization code',
            headers: {
              Location: {
                schema: { type: 'string' },
                description: 'https://wallet.example.com/callback?code=AUTH_CODE&state=STATE',
              },
            },
          },
          '400': {
            description: 'Invalid or expired request_uri',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/token': {
      post: {
        tags: ['OID4VCI'],
        summary: 'Token endpoint (DPoP)',
        description: `**Step 3 of OID4VCI authorization-code flow.**

Exchange an authorization code for a **DPoP-bound access token** and a \`c_nonce\` for the credential proof. Implements RFC 6749 token endpoint + RFC 9449 DPoP.

**DPoP proof (required):** Include a \`DPoP\` header containing a proof JWT with:
- \`typ: "dpop+jwt"\`
- \`alg: "ES256"\`
- \`jwk\`: client P-256 public key (JWK)
- \`htm: "POST"\`, \`htu: "http://localhost:3000/oauth/token"\`
- \`iat\`: current timestamp (accepted within ±30 seconds)

**PKCE verification:** Include \`code_verifier\` matching the \`code_challenge\` from PAR.

**Returns:** \`access_token\` (DPoP-bound), \`token_type: "DPoP"\`, \`expires_in\`, and \`c_nonce\` to use in the credential key proof.`,
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': {
              schema: {
                type: 'object',
                required: ['grant_type', 'code', 'redirect_uri', 'client_id', 'code_verifier'],
                properties: {
                  grant_type: { type: 'string', enum: ['authorization_code'], example: 'authorization_code' },
                  code: { type: 'string', description: 'Authorization code from the authorize redirect', example: 'AUTH_CODE' },
                  redirect_uri: { type: 'string', format: 'uri', example: 'https://wallet.example.com/callback' },
                  client_id: { type: 'string', description: 'The client DID', example: 'did:key:zDnaeWJjH...' },
                  code_verifier: { type: 'string', description: 'PKCE code verifier (43-128 chars)', example: 'dBjftJeZ4C...' },
                },
              },
            },
          },
        },
        parameters: [
          {
            name: 'DPoP',
            in: 'header',
            required: true,
            schema: { type: 'string' },
            description: 'DPoP proof JWT (RFC 9449)',
          },
        ],
        responses: {
          '200': {
            description: 'Token issued',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['access_token', 'token_type', 'expires_in', 'c_nonce'],
                  properties: {
                    access_token: { type: 'string', example: 'eyJhbGciOiJFUzI1...' },
                    token_type: { type: 'string', enum: ['DPoP'], example: 'DPoP' },
                    expires_in: { type: 'integer', example: 300 },
                    c_nonce: { type: 'string', description: 'Nonce for key proof JWT at credential endpoint', example: 'tZignsnFbp' },
                    c_nonce_expires_in: { type: 'integer', example: 300 },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid grant, missing PKCE verifier, or malformed request',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Invalid DPoP proof or expired/reused authorization code',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/nonce': {
      post: {
        tags: ['OID4VCI'],
        summary: 'Refresh c_nonce',
        description: `Refresh the \`c_nonce\` used as an anti-replay mechanism in the credential key proof JWT. Call this if the \`c_nonce\` from the token response has expired before the credential request is sent.

**Authentication:** Requires the DPoP-bound access token (\`Authorization: DPoP <token>\`) and a fresh \`DPoP\` proof header.`,
        security: [{ DPoP: [] }],
        parameters: [
          {
            name: 'DPoP',
            in: 'header',
            required: true,
            schema: { type: 'string' },
            description: 'DPoP proof JWT for this request',
          },
        ],
        responses: {
          '200': {
            description: 'Fresh c_nonce',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['c_nonce', 'c_nonce_expires_in'],
                  properties: {
                    c_nonce: { type: 'string', example: 'Qk9wR3...' },
                    c_nonce_expires_in: { type: 'integer', example: 300 },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Invalid DPoP proof or token',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/credentials': {
      post: {
        tags: ['OID4VCI'],
        summary: 'Credential endpoint',
        description: `**Step 4 (final) of OID4VCI authorization-code flow.**

Request a Verifiable Credential using the DPoP-bound access token. The client must include a **key proof JWT** (\`openid4vci-proof+jwt\`) to prove possession of the holder key.

**Key proof JWT (\`proof\` parameter):**
\`\`\`json
{
  "proof_type": "jwt",
  "jwt": "<compact JWT>"
}
\`\`\`

The proof JWT must have:
- \`typ: "openid4vci-proof+jwt"\`
- \`alg: "ES256"\`
- \`kid\`: holder DID or key ID
- \`iss\`: client DID
- \`aud\`: issuer URL (\`http://localhost:3000\`)
- \`iat\`: current timestamp
- \`nonce\`: the \`c_nonce\` from the token response

**Returns:** A credential in the requested format (\`vc+sd-jwt\` or \`mso_mdoc\`).

**Authentication:** Requires DPoP-bound access token (\`Authorization: DPoP <token>\`) + \`DPoP\` proof header.`,
        security: [{ DPoP: [] }],
        parameters: [
          {
            name: 'DPoP',
            in: 'header',
            required: true,
            schema: { type: 'string' },
            description: 'DPoP proof JWT for this request',
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['format', 'proof'],
                properties: {
                  format: {
                    type: 'string',
                    enum: ['vc+sd-jwt', 'mso_mdoc'],
                    description: 'Requested credential format',
                    example: 'vc+sd-jwt',
                  },
                  credential_configuration_id: {
                    type: 'string',
                    description: 'Credential configuration ID from issuer metadata',
                    example: 'UniversityDegreeCredential',
                  },
                  proof: {
                    type: 'object',
                    required: ['proof_type', 'jwt'],
                    properties: {
                      proof_type: { type: 'string', enum: ['jwt'], example: 'jwt' },
                      jwt: { type: 'string', description: 'Key proof JWT (openid4vci-proof+jwt)', example: 'eyJhbGci...' },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Credential issued',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['format', 'credential'],
                  properties: {
                    format: { type: 'string', example: 'vc+sd-jwt' },
                    credential: { type: 'string', description: 'The issued credential (SD-JWT or base64url mso_mdoc)', example: 'eyJ...' },
                    c_nonce: { type: 'string', description: 'Refreshed nonce for subsequent requests' },
                    c_nonce_expires_in: { type: 'integer' },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid proof JWT or unsupported format',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'Invalid DPoP proof or access token',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/vp/initiate': {
      post: {
        tags: ['OID4VP'],
        summary: 'Initiate VP presentation request',
        description: `**Step 1 of OID4VP flow — verifier initiates.**

A verifier calls this endpoint to start a Verifiable Presentation request session. The server creates a VP session and returns a \`request_uri\` that the wallet uses to fetch the signed JAR (JWT Authorization Request) request object.

**DCQL query:** Specify the credentials to request using a DCQL (Digital Credential Query Language) query. Example: requesting specific claims from an SD-JWT VC.

**Returns:**
- \`request_uri\`: URL the wallet fetches to get the signed request object (\`GET /oauth/request/{id}\`)
- \`nonce\`: Anti-replay nonce the wallet must bind into the KB-JWT
- \`sessionId\`: Poll \`GET /oauth/vp-result/{sessionId}\` for the verification result

**Authentication:** Requires a valid Bearer JWT with role \`verifier\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['dcqlQuery'],
                properties: {
                  dcqlQuery: {
                    type: 'object',
                    description: 'DCQL query specifying requested credential(s) and claims',
                    example: {
                      credentials: [{
                        id: 'university_degree',
                        format: 'dc+sd-jwt',
                        meta: { vct_values: ['UniversityDegreeCredential'] },
                        claims: [{ path: ['name'] }, { path: ['degree'] }],
                      }],
                    },
                  },
                  redirectUri: {
                    type: 'string',
                    format: 'uri',
                    description: 'Optional redirect URI for browser-based flows',
                    example: 'https://verifier.example.com/result',
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'VP session created',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['sessionId', 'requestUri', 'nonce'],
                  properties: {
                    sessionId: { type: 'string', format: 'uuid', example: 'b2c3d4e5-...' },
                    requestUri: { type: 'string', example: 'http://localhost:3000/oauth/request/b2c3d4e5-...' },
                    nonce: { type: 'string', description: 'Nonce the wallet must bind in KB-JWT', example: 'sHjt2P...' },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller is not a verifier',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/request/{id}': {
      get: {
        tags: ['OID4VP'],
        summary: 'Get signed JAR request object',
        description: `**Step 2 of OID4VP flow — wallet fetches request.**

The wallet fetches the signed **JWT Authorization Request (JAR)** object for a VP session. The JAR is a signed JWT containing the full authorization request parameters including the DCQL query and nonce.

**Response:** \`application/oauth-authz-req+jwt\` — a compact JWT signed by the verifier's P-256 key (ES256) containing:
- \`client_id\`: verifier DID
- \`response_uri\`: \`http://localhost:3000/oauth/direct_post\`
- \`response_mode: "direct_post"\`
- \`nonce\`: anti-replay nonce for KB-JWT
- \`dcql_query\`: the DCQL credential query

**Public endpoint** — no authentication required. The JAR is self-contained and signed.`,
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
            description: 'VP session ID',
          },
        ],
        responses: {
          '200': {
            description: 'Signed JAR request object',
            content: {
              'application/oauth-authz-req+jwt': {
                schema: {
                  type: 'string',
                  description: 'Compact JWT serialization of the authorization request',
                  example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ...',
                },
              },
            },
          },
          '404': {
            description: 'VP session not found or expired',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/direct_post': {
      post: {
        tags: ['OID4VP'],
        summary: 'Submit VP response (direct_post)',
        description: `**Step 3 of OID4VP flow — wallet submits presentation.**

The wallet posts the Verifiable Presentation response to this endpoint. The VP token must be an **SD-JWT VC with a Key Binding JWT (KB-JWT)** appended (\`issuerJwt~disc1~disc2~kbJwt\`).

**KB-JWT requirements (HAIP 1.0):**
- \`typ: "kb+jwt"\`
- \`alg: "ES256"\`
- \`nonce\`: matches the nonce from the JAR request object
- \`aud\`: verifier DID (the \`client_id\` from the JAR)
- \`sd_hash\`: SHA-256 of the disclosed SD-JWT (\`issuerJwt~disc1~disc2~\` with trailing \`~\`)
- Signed with the holder's P-256 key matching \`cnf.jwk\` in the issuer JWT

**The server will:**
1. Verify KB-JWT signature and nonce binding
2. Verify the SD-JWT issuer signature and disclosure hashes
3. Check trust registry and Token Status List
4. Store the result in the VP session (retrievable via \`GET /oauth/vp-result/{id}\`)`,
        requestBody: {
          required: true,
          content: {
            'application/x-www-form-urlencoded': {
              schema: {
                type: 'object',
                required: ['vp_token', 'presentation_submission'],
                properties: {
                  vp_token: {
                    type: 'string',
                    description: 'SD-JWT VC with KB-JWT: issuerJwt~disc1~...~kbJwt',
                    example: 'eyJ...~disc1~eyJraWQ...',
                  },
                  presentation_submission: {
                    type: 'string',
                    description: 'JSON-encoded Presentation Submission object mapping DCQL query to credential',
                    example: '{"id":"submission-1","definition_id":"...","descriptor_map":[...]}',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Presentation accepted and verified',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['redirect_uri'],
                  properties: {
                    redirect_uri: { type: 'string', description: 'Redirect URL with verification result (if verifier set redirectUri)', example: 'https://verifier.example.com/result?session=...' },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid VP token, malformed KB-JWT, or missing parameters',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '401': {
            description: 'KB-JWT signature invalid or nonce mismatch',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '422': {
            description: 'SD-JWT verification failed or credential revoked',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/oauth/vp-result/{id}': {
      get: {
        tags: ['OID4VP'],
        summary: 'Poll VP verification result',
        description: `**Step 4 of OID4VP flow — verifier polls for result.**

The verifier polls this endpoint after initiating a VP session to check whether the wallet has submitted a presentation and whether it passed verification.

**Session states:**

| State | Meaning |
|-------|---------|
| \`pending\` | Waiting for wallet to submit presentation |
| \`verified\` | Presentation received and all checks passed |
| \`failed\` | Presentation received but verification failed (invalid proof, revoked credential, untrusted issuer) |
| \`expired\` | Session timed out without a response |

**Authentication:** Requires the same Bearer JWT that initiated the session (verifier role).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
            description: 'VP session ID returned by POST /oauth/vp/initiate',
          },
        ],
        responses: {
          '200': {
            description: 'VP session result',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['sessionId', 'state'],
                  properties: {
                    sessionId: { type: 'string', format: 'uuid' },
                    state: { type: 'string', enum: ['pending', 'verified', 'failed', 'expired'], example: 'verified' },
                    disclosedClaims: {
                      type: 'object',
                      description: 'Present when state=verified. The claims disclosed by the wallet.',
                      example: { name: 'Alice Smith', degree: 'Bachelor of Science' },
                    },
                    error: {
                      type: 'string',
                      description: 'Present when state=failed. Machine-readable error code.',
                      example: 'CREDENTIAL_REVOKED',
                    },
                    verifiedAt: { type: 'string', format: 'date-time' },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '403': {
            description: 'Caller did not initiate this session',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          '404': {
            description: 'Session not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
  },
}
