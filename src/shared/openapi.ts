// src/shared/openapi.ts

export const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'DID + ZKP REST API',
    version: '1.0.0',
    description:
      'A production-ready REST API built with Bun and Hono that implements the W3C Decentralized Identity (DID) protocol with Zero-Knowledge Proofs via BBS+ signatures for selective disclosure of Verifiable Credentials.',
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
    },
  },
  paths: {
    '/v1/auth/challenge': {
      post: {
        tags: ['Authentication'],
        summary: 'Request authentication challenge',
        description: 'Get a one-time challenge nonce associated with a DID for authentication.',
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
        description: 'Submit the signature of the nonce to get a 15-minute JWT session token.',
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
        description: 'Generate a new did:key identity document. The private key is returned only once.',
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
        description: 'Retrieve the authenticated caller\'s DID and document.',
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
        description: 'Resolve any active DID document by its DID identifier.',
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
        description: 'Deactivate a DID. The path did must match the authenticated caller\'s own DID.',
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
        description: 'Get a list of all credentials issued by the authenticated caller. Requires \'issuer\' role.',
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
        description:
          'Issue a new BBS+-signed Verifiable Credential. Requester must be an \'issuer\' with an active trust attestation.',
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
        description: 'Fetch a full credential by its ID. Caller must be the issuer or the subject.',
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
        description: 'Revoke a Verifiable Credential. Caller must be the issuer of the credential.',
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
        description: 'Public endpoint to query if a credential is active, revoked, or expired.',
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
        description:
          'Derive a new Verifiable Presentation revealing only selected claims from a BBS+-signed credential. Caller must be the subject.',
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
        description: 'Verify a presentation proof, trust chains, and revocation status. Caller must be a verifier.',
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
        description: 'Fetch details of a derived presentation by ID. Caller must be the subject.',
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
        description: 'Get a list of all active trusted issuer DIDs. Public access.',
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
        description: 'Check if a specific issuer DID is currently active in the trust registry.',
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
        description: 'Vouch for an issuer DID by granting an attestation VC. Caller must be an \'attester\'.',
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
        description: 'Revoke an active attestation by ID. Caller must be an \'attester\'.',
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
