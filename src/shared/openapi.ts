// src/shared/openapi.ts

export const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'DID + ZKP REST API',
    version: '1.2.0',
    description: `A production-ready REST API built with **Bun + Hono** that implements the W3C Decentralized Identity (DID) protocol with **Zero-Knowledge Proofs via BBS+ signatures** for privacy-preserving selective disclosure of Verifiable Credentials.

---

## Core Concepts

### Actors and roles
Every participant is assigned one of four roles:

| Role | Responsibility |
|------|----------------|
| **attester** | Trust anchor — vouches for which issuers are allowed to sign credentials |
| **issuer** | Signs BBS+ Verifiable Credentials for subjects (requires active trust attestation) |
| **subject** | Holds credentials; derives privacy-preserving presentations with selective disclosure |
| **verifier** | Validates presentations against proof, trust chain, and revocation status |

### Authentication — two paths

**Path A — Email/password (v1.2, recommended for user-facing apps):**
1. \`POST /v1/auth/signup\` — create account; a \`did:key\` is generated automatically and returned
2. \`POST /v1/auth/login\` — exchange email + password for a **JWT Bearer token**
3. Use the token as \`Authorization: Bearer <token>\` on protected endpoints

**Path B — DID challenge–response (cryptographic, for autonomous agents/services):**
1. \`POST /v1/dids\` — create a raw DID keypair without a user account
2. \`POST /v1/auth/challenge\` — receive a one-time nonce
3. Sign \`"{did}:{nonce}"\` with your Ed25519 private key
4. \`POST /v1/auth/verify\` — exchange the signature for a **JWT Bearer token**

Both paths issue the same JWT format and grant the same access to protected endpoints.

### Typical end-to-end flow (email auth)

\`\`\`
1. [attester]  POST /v1/auth/signup             → Create account (role defaults to subject; upgrade via admin)
2. [admin]     POST /v1/admin/users/{id}/role   → Upgrade attester/issuer roles
3. [attester]  POST /v1/auth/login              → Get JWT
4. [attester]  POST /v1/trust/attest            → Grant issuer trust attestation
5. [issuer]    POST /v1/auth/login              → Get JWT
6. [issuer]    POST /v1/credentials/issue       → Issue BBS+ credential to subject
7. [subject]   POST /v1/auth/login              → Get JWT
8. [subject]   POST /v1/presentations/derive    → Derive selective-disclosure VP
9. [verifier]  POST /v1/presentations/verify    → Verify proof + trust chain + revocation
\`\`\`

### Organizations
Users can create and manage **organizations** (e.g., universities, companies) that hold their own \`did:key\`. Organization members share the org DID for issuing credentials at an institutional level.

### Privacy model (BBS+ / ZKP)
BBS+ signatures allow a credential holder to create a cryptographic proof that reveals only a chosen subset of claims. The verifier learns only what the subject explicitly discloses — no other claims are visible, and the proof is mathematically indistinguishable from a proof over the full credential.

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
        description: 'Provide your 15-minute JWT session token received from `/v1/auth/verify`.',
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
          did: { type: 'string', example: 'did:key:z6Mku...' },
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
          did: { type: 'string', example: 'did:key:z6Mku...' },
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
    },
  },
  tags: [
    { name: 'Email Auth', description: 'Email/password signup, login, and password reset (v1.2)' },
    { name: 'Users', description: 'User profile management' },
    { name: 'Admin', description: 'Administrative operations (requires X-Admin-Secret header)' },
    { name: 'Organizations', description: 'Organization management — create orgs, manage members, and send invites' },
    { name: 'Authentication', description: 'DID-based challenge–response authentication (cryptographic path)' },
    { name: 'DID Management', description: 'Create and resolve did:key identities' },
    { name: 'Verifiable Credentials', description: 'Issue, retrieve, and revoke BBS+-signed Verifiable Credentials' },
    { name: 'Verifiable Presentations', description: 'Derive and verify selective-disclosure Verifiable Presentations' },
    { name: 'Trust Registry', description: 'Manage trust attestations between attesters and issuers' },
  ],
  paths: {
    '/v1/auth/signup': {
      post: {
        tags: ['Email Auth'],
        summary: 'Sign up with email and password',
        description: `Create a new user account. A \`did:key\` identity is generated automatically and linked to the account — you do not need to call \`POST /v1/dids\` separately.

**Returns:** A JWT Bearer token and the user profile including the generated DID.

**Role:** All new accounts start with role \`subject\`. Use \`POST /v1/admin/users/{id}/role\` to upgrade to \`issuer\`, \`verifier\`, or \`attester\`.

**Constraints:**
- Email must be unique (409 \`EMAIL_TAKEN\` if already registered)
- Password must be ≥ 8 characters
- The private key for the generated DID is returned **only once** and not stored — save it if you intend to use DID challenge-response auth in parallel`,
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
        description: `Create a new organization with its own \`did:key\` identity. The caller becomes the organization **owner**.

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
        description: `**Step 1 of 2 — DID-based authentication.**

Submit your \`did:key\` identifier to receive a one-time challenge nonce. This is the first step of the challenge–response authentication flow used throughout the API.

**How it works:**
1. Call this endpoint with your DID.
2. The server generates a short-lived nonce (TTL ~5 minutes) and stores a \`challengeId\` ↔ nonce pair.
3. Sign the string \`"{did}:{nonce}"\` with your **Ed25519 private key** (the one generated at DID creation).
4. Pass \`did\`, \`challengeId\`, and the hex-encoded signature to \`POST /v1/auth/verify\` to receive a JWT.

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
                    description: 'The did:key identifier of the authenticating actor.',
                    example: 'did:key:z6MkuG2B6Q... (Ed25519)',
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
                      example: 'd9b7f5c2... (hex nonce)',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Invalid input',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'DID not found or deactivated',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/auth/verify': {
      post: {
        tags: ['Authentication'],
        summary: 'Verify challenge signature',
        description: `**Step 2 of 2 — DID-based authentication.**

Exchange the signed challenge nonce for a short-lived JWT session token. This token must be included as a \`Bearer\` header on every protected endpoint.

**How to sign the nonce:**
- Concatenate: \`"{did}:{nonce}"\` (UTF-8 string)
- Sign with your **Ed25519 private key**
- Hex-encode the resulting 64-byte signature

**Token details:**
- Format: JWT (HS256 or EdDSA depending on env config)
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
                    example: 'did:key:z6Mku...',
                  },
                  challengeId: {
                    type: 'string',
                    format: 'uuid',
                    example: 'a58b9c8f-ddec-44a5-a3b5-732346dac1dd',
                  },
                  signature: {
                    type: 'string',
                    description: 'Hex-encoded Ed25519 signature of (did + ":" + nonce)',
                    example: '8f3ce...',
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
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '401': {
            description: 'Challenge expired or signature verification failed',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/dids': {
      post: {
        tags: ['DID Management'],
        summary: 'Create a new DID',
        description: `Generate a new \`did:key\` identity with an Ed25519 keypair. This is the entry point for every actor in the system — you must create a DID before you can authenticate.

**Roles and their capabilities:**

| Role | Can do |
|------|--------|
| \`subject\` | Hold credentials, derive selective presentations |
| \`issuer\` | Issue BBS+-signed Verifiable Credentials (requires trust attestation) |
| \`verifier\` | Verify Verifiable Presentations |
| \`attester\` | Grant/revoke trust attestations to issuers |

**Critical — private key handling:**
The \`privateKey\` field is returned **only once**, at creation time. The server does **not** store it. If you lose the private key, you lose the ability to authenticate as this DID and it cannot be recovered.

**What is a \`did:key\`?**
A self-describing, self-contained identifier derived directly from the public key. No blockchain or registry is required to create one. The DID document is stored server-side for resolution by other participants.`,
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
                      example: 'did:key:z6Mku...',
                    },
                    document: {
                      type: 'object',
                      description: 'The W3C DID document representation.',
                    },
                    privateKey: {
                      type: 'string',
                      description: 'Raw private key (returned ONLY on creation)',
                      example: '3a4f6...',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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
- Retrieve your own DID document (contains your public key, verification methods, and service endpoints)
- Verify your role before attempting role-restricted operations

**Authentication:** Requires a valid \`Bearer\` JWT from \`POST /v1/auth/verify\`.`,
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
                    did: {
                      type: 'string',
                      example: 'did:key:z6Mku...',
                    },
                    document: {
                      type: 'object',
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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
- An issuer resolves a subject's DID to retrieve their public key before issuing a credential
- A verifier resolves an issuer's DID to inspect their verification methods
- Any party performs discovery without needing authentication

**Deactivated DIDs:** Returns \`404\`. Once a DID is deactivated via \`DELETE /v1/dids/{did}\`, it cannot be resolved.

**DID document structure** follows the [W3C DID Core spec](https://www.w3.org/TR/did-core/) and includes \`verificationMethod\`, \`authentication\`, and \`assertionMethod\` entries derived from the Ed25519 public key.`,
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
            description: 'The target did:key identifier.',
            example: 'did:key:z6Mku...',
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
                  properties: {
                    document: {
                      type: 'object',
                    },
                  },
                },
              },
            },
          },
          '404': {
            description: 'DID not found or deactivated',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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

**Use cases:** Rotating an identity, retiring a test DID, or responding to a key compromise.

**Authentication:** Requires a valid \`Bearer\` JWT from \`POST /v1/auth/verify\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
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
                  properties: {
                    success: {
                      type: 'boolean',
                      example: true,
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller does not own this DID)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'DID not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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

**Response shape:** An array of full credential records including status (\`active\`, \`revoked\`, \`expired\`), subject DID, credential type, and BBS+ signature data.

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
                    credentials: {
                      type: 'array',
                      items: {
                        type: 'object',
                      },
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller role is not issuer)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/credentials/issue': {
      post: {
        tags: ['Verifiable Credentials'],
        summary: 'Issue a new Verifiable Credential',
        description: `Signs and persists a new **BBS+ Verifiable Credential** (VC) for a given subject.

**Prerequisites before calling this endpoint:**
1. Caller must have the \`issuer\` role
2. The calling issuer DID must have an **active trust attestation** in the trust registry (granted via \`POST /v1/trust/attest\`). Without attestation, issuance is rejected with \`403\`.
3. The \`subjectDid\` must be an existing, active DID registered with this server.

**Why BBS+ signatures?**
BBS+ (Boneh–Boyen–Shacham) allows subjects to later derive **selective-disclosure presentations** — proving specific claims from this credential without revealing the full set. Each claim in \`claims\` becomes a separately disclosable statement.

**Claim design tips:**
- Keep claims atomic (one fact per key): \`{"degree": "BSc", "gpa": "3.9"}\` not \`{"education": {...}}\`
- Avoid nesting — BBS+ disclosure works at the top-level key granularity

**Rate limit:** 10 requests per minute per issuer to prevent credential spam.

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
                    example: 'did:key:z6Mku...',
                  },
                  credentialType: {
                    type: 'array',
                    items: {
                      type: 'string',
                    },
                    minItems: 1,
                    example: ['UniversityDegreeCredential'],
                  },
                  claims: {
                    type: 'object',
                    description: 'Subject attributes to sign.',
                    example: {
                      name: 'Alice Smith',
                      degree: 'Bachelor of Science',
                      gpa: '3.9',
                    },
                  },
                  expiresAt: {
                    type: 'string',
                    format: 'date-time',
                    description: 'ISO-8601 string of credential expiration.',
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
                  description: 'The signed Verifiable Credential object containing BBS+ signatures.',
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller role is not issuer or lacks active attestation)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/credentials/{id}': {
      get: {
        tags: ['Verifiable Credentials'],
        summary: 'Get credential details',
        description: `Retrieves the full Verifiable Credential record by its ID, including the BBS+ signature, credential type, all claims, issuance date, and current status.

**Access control:** Only the **issuer** who created the credential or the **subject** it was issued to can fetch it. Any other caller receives \`403 Forbidden\`.

**Credential ID format:** URN UUID — e.g. \`urn:uuid:7179010f-6240-424a-ba92-a16912384aee\`. The ID is returned in the response body of \`POST /v1/credentials/issue\` and should be communicated out-of-band to the subject (e.g. via a secure channel or QR code).

**Authentication:** Requires a valid \`Bearer\` JWT (issuer or subject role).`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
            description: 'The credential ID (URN/UUID).',
            example: 'urn:uuid:7179010f-6240-424a-ba92-a16912384aee',
          },
        ],
        responses: {
          '200': {
            description: 'Credential record retrieved',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller is neither issuer nor subject)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'Credential not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/credentials/{id}/revoke': {
      post: {
        tags: ['Verifiable Credentials'],
        summary: 'Revoke credential',
        description: `Marks a Verifiable Credential as **revoked**. Once revoked, the credential status endpoint returns \`"revoked"\` and any attempt to derive a new presentation from it will fail with \`422 Unprocessable Entity\`.

**Access control:** Only the **issuer** who originally signed the credential can revoke it. The subject cannot revoke their own credential.

**Effect on existing presentations:** Previously derived presentations are not automatically invalidated in storage, but when a verifier calls \`POST /v1/presentations/verify\`, the verification result will include \`"credentialStatus": "revoked"\` and \`"valid": false\`.

**Irreversibility:** Revocation cannot be undone through the API. If you need to re-issue, create a new credential.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`issuer\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
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
                  properties: {
                    success: {
                      type: 'boolean',
                      example: true,
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller is not the issuer)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'Credential not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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
| \`revoked\` | Explicitly revoked by the issuer |
| \`expired\` | Past the \`expiresAt\` date set at issuance |
| \`not_found\` | No credential with this ID exists |

**Tip for verifiers:** Call this endpoint before (or alongside) \`POST /v1/presentations/verify\` to short-circuit verification on credentials that are already known to be revoked or expired.`,
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
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
                    status: {
                      type: 'string',
                      enum: ['active', 'revoked', 'expired', 'not_found'],
                      example: 'active',
                    },
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
        summary: 'Derive selective-disclosure presentation',
        description: `Creates a **Verifiable Presentation (VP)** that cryptographically proves a subset of claims from a BBS+-signed credential — without revealing any unrequested claims to the verifier.

**This is the core ZKP feature of the API.** A subject holding a credential with claims \`{name, degree, gpa, nationality}\` can prove only \`{name, degree}\` to a verifier, with the proof still being mathematically valid against the full credential signature.

**How to use:**
1. Identify the \`credentialId\` of the credential you want to present (received from the issuer)
2. Choose which claim keys to reveal in \`revealedClaims\` (must match keys in the original \`claims\` object)
3. The API returns a signed VP object you can share with any verifier

**Prerequisites:**
- Caller must own the credential (be its \`subjectDid\`)
- The underlying credential must have status \`active\` — revoked or expired credentials return \`422\`

**Access control:** Requires role \`subject\`.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`subject\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['credentialId', 'revealedClaims'],
                properties: {
                  credentialId: {
                    type: 'string',
                    example: 'urn:uuid:7179010f-6240-424a-ba92-a16912384aee',
                  },
                  revealedClaims: {
                    type: 'array',
                    items: {
                      type: 'string',
                    },
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
                  description: 'The derived VP with BBS+ selective disclosure proof.',
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller role is not subject or caller does not own the credential)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '422': {
            description: 'Unprocessable Entity (e.g., credential is revoked or expired)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/presentations/verify': {
      post: {
        tags: ['Verifiable Presentations'],
        summary: 'Verify Verifiable Presentation',
        description: `The end-to-end verification endpoint for verifiers. Accepts a full VP object and runs a **multi-step verification pipeline**:

1. **Proof verification** — validates the BBS+ selective-disclosure cryptographic proof against the issuer's public key
2. **Trust chain check** — confirms the credential's issuer has an active attestation in the trust registry
3. **Revocation check** — confirms the underlying credential has not been revoked or expired

**Response fields explained:**

| Field | Description |
|-------|-------------|
| \`valid\` | \`true\` only if ALL three checks above pass |
| \`disclosedClaims\` | The subset of claims the subject chose to reveal |
| \`issuerTrusted\` | Whether the issuer DID is in the active trust registry |
| \`credentialStatus\` | \`active\`, \`revoked\`, or \`expired\` |

**Important:** A \`200\` response does not mean the credential is valid — always check the \`valid\` field. A verifier may receive a \`200\` with \`"valid": false\` when the issuer is no longer trusted or the credential was revoked after the VP was derived.

**Access control:** Requires role \`verifier\`.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`verifier\`.`,
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
                    description: 'The full Verifiable Presentation object.',
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
                    valid: {
                      type: 'boolean',
                      example: true,
                    },
                    disclosedClaims: {
                      type: 'object',
                      description: 'The subset of claims disclosed in the presentation.',
                      example: {
                        name: 'Alice Smith',
                        degree: 'Bachelor of Science',
                      },
                    },
                    issuerTrusted: {
                      type: 'boolean',
                      example: true,
                    },
                    credentialStatus: {
                      type: 'string',
                      example: 'active',
                    },
                  },
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller role is not verifier)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
    '/v1/presentations/{id}': {
      get: {
        tags: ['Verifiable Presentations'],
        summary: 'Get presentation details',
        description: `Retrieves a previously derived Verifiable Presentation by its ID. Useful for subjects to review past presentations or re-share a VP with a new verifier without re-deriving it.

**Access control:** Only the **subject** who derived the presentation can fetch it. This prevents verifiers or third parties from enumerating a subject's presentation history.

**When to use:** If a verifier needs the same VP re-sent (e.g., network failure), the subject can retrieve and re-share this stored copy rather than calling \`POST /v1/presentations/derive\` again.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`subject\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
            description: 'The presentation ID.',
          },
        ],
        responses: {
          '200': {
            description: 'Presentation retrieved successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller is not subject)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'Presentation not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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
                    issuers: {
                      type: 'array',
                      items: {
                        type: 'string',
                      },
                      example: ['did:key:z6Mku...'],
                    },
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

**When to use:**
- Before accepting a credential from an issuer out-of-band (e.g., a QR-scanned credential without going through \`POST /v1/presentations/verify\`)
- As a lightweight trust probe without fetching the full trusted-issuer list

**Note:** The \`POST /v1/presentations/verify\` endpoint already performs this check internally. Only call this endpoint separately if you need a standalone trust check.`,
        parameters: [
          {
            name: 'did',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
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
                  properties: {
                    trusted: {
                      type: 'boolean',
                      example: true,
                    },
                  },
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
        description: `Grants a trust attestation to an issuer DID, adding it to the **trust registry**. Until attested, an issuer cannot create credentials — the \`POST /v1/credentials/issue\` endpoint will reject them with \`403\`.

**The trust model:**
This API uses a **delegated trust** model. Attesters act as trust anchors (similar to a Certificate Authority). They vouch for which issuers are allowed to sign credentials. Verifiers then check this registry when validating presentations.

**Attestation lifecycle:**
- An attestation is active from creation until its \`expiresAt\` (if set) or until explicitly revoked via \`POST /v1/trust/attest/{id}/revoke\`
- An issuer DID can hold multiple simultaneous attestations from different attesters
- If all attestations for an issuer expire or are revoked, the issuer loses the ability to issue new credentials

**Access control:** Requires role \`attester\`.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`attester\`.`,
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['issuerDid'],
                properties: {
                  issuerDid: {
                    type: 'string',
                    example: 'did:key:z6Mku...',
                  },
                  expiresAt: {
                    type: 'string',
                    format: 'date-time',
                    description: 'Optional expiration timestamp.',
                    example: '2030-12-31T23:59:59Z',
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'Attestation granted successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  description: 'The signed attestation VC.',
                },
              },
            },
          },
          '400': {
            description: 'Validation error',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller role is not attester)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
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

**Use cases:** Key compromise response, policy violation, routine rotation of trusted issuers.

**Authentication:** Requires a valid \`Bearer\` JWT with role \`attester\`.`,
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: {
              type: 'string',
            },
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
                  properties: {
                    success: {
                      type: 'boolean',
                      example: true,
                    },
                  },
                },
              },
            },
          },
          '401': {
            description: 'Unauthorized jwt session',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '403': {
            description: 'Forbidden (caller is not an attester)',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
          '404': {
            description: 'Attestation not found',
            content: {
              'application/json': {
                schema: {
                  $ref: '#/components/schemas/ErrorResponse',
                },
              },
            },
          },
        },
      },
    },
  },
}
