# DID + ZKP REST API

A REST API for issuing, sharing, and verifying tamper-proof digital credentials — degrees, certificates, badges — where users control exactly what they share.

Developers can use this API to add trusted credential management to any platform: a university issuing digital diplomas, a company managing employee certifications, or an app that lets users prove facts about themselves without oversharing. Built with **Bun** and **Hono**, production-ready and OWASP-compliant out of the box.

---

## Overview

This API enables four actor roles to participate in a full decentralized identity ecosystem:

| Role | Description |
|---|---|
| **Subject** | Holds credentials and creates selective-disclosure presentations |
| **Issuer** | Signs and issues Verifiable Credentials to subjects |
| **Verifier** | Verifies presented credentials and their proofs |
| **Attester** | Acts as a trust registry, vouching for issuer authority |

### Key Capabilities

- **Email/password accounts** — sign up and log in; a `did:key` is auto-generated per account (v1.2)
- **Organizations** — group accounts under a shared institutional DID (v1.2)
- **`did:key`** — self-sovereign DID generation (Ed25519 + BLS12-381 G2 keys)
- **BBS+ Signatures** (`bbs-2023`) — sign multi-claim credentials and derive selective-disclosure proofs
- **W3C VC Data Model 2.0** — `DataIntegrityProof` with JSON-LD, fully spec-compliant
- **DID Auth** — challenge/response authentication using Ed25519 key signatures (alternative path)
- **Trust Registry** — attesters issue attestation VCs to authorize issuers
- **OWASP API Security Top 10** — compliant security controls throughout

---

## Identity Lifecycle

The full lifecycle spans five phases:

1. **Account & role setup** — sign up, get roles assigned
2. **Organization setup** — create an institutional identity, invite members
3. **Trust setup** — attester vouches for the issuer
4. **Credential issuance** — issuer signs a BBS+ VC for a subject
5. **Selective-disclosure verification** — subject reveals only chosen claims

### End-to-End Sequence

```mermaid
sequenceDiagram
    autonumber
    actor AD as 🛡️ Admin
    actor AT as 🔐 Attester
    actor OW as 🏛️ Org Owner (Issuer)
    actor SU as 👤 Subject
    actor VE as 🔍 Verifier
    participant API as DID + ZKP API

    rect rgb(220, 235, 255)
        Note over AD,API: Phase 1 — Account & Role Setup

        OW->>API: POST /v1/auth/signup { email, password, name }
        API-->>OW: { token, user: { id, did, role:"subject" } }

        AT->>API: POST /v1/auth/signup { email, password, name }
        API-->>AT: { token, user: { id, did, role:"subject" } }

        SU->>API: POST /v1/auth/signup { email, password, name }
        API-->>SU: { token, user: { id, did, role:"subject" } }

        VE->>API: POST /v1/auth/signup { email, password, name }
        API-->>VE: { token, user: { id, did, role:"subject" } }

        Note over AD: Admin upgrades roles using X-Admin-Secret header
        AD->>API: POST /v1/admin/users/{attesterUserId}/role { role:"attester" }
        API-->>AD: { success: true }

        AD->>API: POST /v1/admin/users/{ownerUserId}/role { role:"issuer" }
        API-->>AD: { success: true }

        AD->>API: POST /v1/admin/users/{verifierUserId}/role { role:"verifier" }
        API-->>AD: { success: true }

        Note over OW,VE: Everyone logs in again to get a fresh JWT reflecting the new role
        OW->>API: POST /v1/auth/login { email, password }
        API-->>OW: { token } ← JWT now carries role:"issuer"

        AT->>API: POST /v1/auth/login { email, password }
        API-->>AT: { token } ← JWT now carries role:"attester"
    end

    rect rgb(255, 243, 220)
        Note over OW,API: Phase 2 — Organization Setup

        OW->>API: POST /v1/organizations { name:"Test University", role:"issuer" }
        Note over API: Creates org with its own did:key (role=issuer)<br/>Owner auto-added as member with role "owner"
        API-->>OW: { id:orgId, name, slug, did:orgDid, memberRole:"owner" }

        Note over OW: Invite existing users by email — added directly as members
        OW->>API: POST /v1/organizations/{orgId}/invites { email, role:"admin" }
        API-->>OW: { userId, memberRole:"admin" }

        Note over OW: Invite someone who hasn't signed up yet
        OW->>API: POST /v1/organizations/{orgId}/invites { email:"newmember@example.com", role:"member" }
        API-->>OW: { inviteToken, expiresAt } ← 72-hour token to share with invitee

        SU->>API: POST /v1/organizations/invites/{inviteToken}/accept {}
        Note over API: Verifies caller email matches invite email (BOLA protection)
        API-->>SU: { success: true }
    end

    rect rgb(220, 255, 230)
        Note over AT,API: Phase 3 — Trust Setup (Attester authorises the Issuer)

        Note over AT: Attester calls the trust endpoint using their personal issuer DID<br/>(the DID embedded in their JWT)
        AT->>API: POST /v1/trust/attest { issuerDid: ownerDid }
        Note over API: Records attestation VC linking attester → issuer<br/>Issuer is now in the trusted registry
        API-->>AT: attestation record { id, issuerDid, attesterDid }
    end

    rect rgb(220, 255, 240)
        Note over OW,SU: Phase 4 — Credential Issuance

        OW->>API: POST /v1/credentials/issue<br/>{ subjectDid, credentialType:["UniversityDegree"], claims:{ name, degree, gpa } }
        Note over API: ① verify Issuer has active trust attestation<br/>② sign all claims with BBS+ (DataIntegrityProof)<br/>③ persist VC with status = active
        API-->>OW: signed Verifiable Credential { id:credId, proof, ... }

        Note over OW,SU: Issuer shares credentialId with Subject out-of-band (QR code, secure message, etc.)
        SU->>API: GET /v1/credentials/{credId}
        API-->>SU: full VC record
    end

    rect rgb(250, 225, 255)
        Note over SU,VE: Phase 5 — Selective Disclosure & Verification

        Note over SU: Subject chooses which claims to reveal<br/>e.g. ["name","degree"] — GPA stays private
        SU->>API: POST /v1/presentations/derive<br/>{ credentialId, revealedClaims:["name","degree"] }
        Note over API: derive BBS+ proof over chosen subset only
        API-->>SU: Verifiable Presentation (VP with ZK proof)

        Note over SU,VE: Subject sends VP to Verifier (off-API channel or direct share)

        VE->>API: POST /v1/presentations/verify { presentation: <VP> }
        Note over API: ① verify BBS+ cryptographic proof<br/>② check Issuer is in trust registry<br/>③ check credential revocation/expiry status
        API-->>VE: { valid:true, disclosedClaims:{ name, degree }, issuerTrusted:true, credentialStatus:"active" }
    end
```

---

### Credential & Presentation State Machine

```mermaid
stateDiagram-v2
    direction TB
    [*] --> Account_Created : POST /v1/auth/signup
    state "Account Created\n(role: subject)" as Account_Created
    state "Role Upgraded\n(issuer / attester / verifier)" as Role_Upgraded
    state "Org Created\n(org DID: issuer)" as Org_Created
    state "Issuer Trusted" as Issuer_Trusted
    state "VC Active" as VC_Active
    state "VP Derived" as VP_Derived

    Account_Created --> Role_Upgraded : POST /v1/admin/users/{id}/role\n(requires X-Admin-Secret)
    Account_Created --> Org_Created : POST /v1/organizations\n(any authenticated user)
    Role_Upgraded --> Issuer_Trusted : POST /v1/trust/attest\n(attester vouches for issuer DID)
    Issuer_Trusted --> VC_Active : POST /v1/credentials/issue\n(issuer + active attestation)

    VC_Active --> VP_Derived : POST /v1/presentations/derive\n(subject · choose claims to reveal)
    VC_Active --> VC_Revoked : POST /v1/credentials/{id}/revoke\n(issuer only · irreversible)
    VC_Active --> VC_Expired : expiresAt timestamp reached

    VP_Derived --> VP_Verified_OK : POST /v1/presentations/verify\n✅ proof valid · issuer trusted · VC active
    VP_Derived --> VP_Verified_FAIL : POST /v1/presentations/verify\n❌ invalid proof OR issuer untrusted OR VC revoked/expired

    VC_Revoked --> [*]
    VC_Expired --> [*]
```

---

### Trust Model at a Glance

```mermaid
flowchart TD
    subgraph Accounts["👥 Account Layer (v1.2)"]
        AT_ACC(["🔐 Attester Account\nemail + password"])
        IS_ACC(["🏛️ Issuer Account\nemail + password"])
        SU_ACC(["👤 Subject Account\nemail + password"])
        VE_ACC(["🔍 Verifier Account\nemail + password"])
        ORG(["🏢 Organization\norgDid (issuer role)"])
    end

    subgraph Protocol["🔗 DID Protocol Layer"]
        TR[("Trust Registry\ntrust_attestations")]
        VC["BBS+ Verifiable\nCredential"]
        VP["Verifiable Presentation\n(selective disclosure)"]
        RES{{"Verification\nResult"}}
    end

    IS_ACC -->|"owns / member of"| ORG
    AT_ACC -->|"POST /v1/trust/attest\ngrant attestation"| TR
    TR -->|"authorises issuance"| IS_ACC
    IS_ACC -->|"POST /v1/credentials/issue\nsign with BBS+"| VC
    VC -->|"issued to"| SU_ACC
    SU_ACC -->|"POST /v1/presentations/derive\nreveal chosen claims only"| VP
    VP -->|"shared with"| VE_ACC
    VE_ACC -->|"POST /v1/presentations/verify"| RES
    TR -.->|"trust check"| RES
    VC -.->|"revocation check"| RES

    style AT_ACC fill:#dce8ff,stroke:#4a90d9
    style IS_ACC fill:#dce8ff,stroke:#4a90d9
    style SU_ACC fill:#dce8ff,stroke:#4a90d9
    style VE_ACC fill:#dce8ff,stroke:#4a90d9
    style ORG fill:#fff3dc,stroke:#e6a817
    style TR fill:#fff3dc,stroke:#e6a817
    style VC fill:#dcffe8,stroke:#27ae60
    style VP fill:#f5dcff,stroke:#8e44ad
    style RES fill:#f0f0f0,stroke:#555
```

> **Privacy guarantee:** The Verifier only ever sees the claims the Subject explicitly included in `revealedClaims`. All other claims in the original credential are cryptographically hidden — the BBS+ proof is mathematically indistinguishable from a proof over the full credential.

---

## Architecture

```
did-zkp/
├── src/
│   ├── domains/
│   │   ├── auth/           # DID challenge/response, JWT sessions, login
│   │   ├── users/          # Email/password accounts, profile, password reset, admin role upgrade
│   │   ├── organizations/  # Org management, member roles, invites
│   │   ├── did/            # DID document management
│   │   ├── credentials/    # VC issuance, revocation, status
│   │   ├── presentation/   # BBS+ selective disclosure, VP verification
│   │   └── trust/          # Attester trust registry
│   ├── shared/
│   │   ├── crypto/         # AES-GCM key encryption, did:key, BBS+ wrappers
│   │   ├── jsonld/         # Offline JSON-LD context loader (no external HTTP)
│   │   └── middleware/     # Rate limiting, security headers, CORS
│   └── index.ts
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
└── docs/
    └── superpowers/
        ├── specs/          # Design specification
        └── plans/          # Implementation plan
```

**Pattern:** Domain-Driven Modular — each domain owns its routes, service, and repository. Shared crypto and middleware are injected via explicit imports.

---

## Tech Stack

| Concern | Library |
|---|---|
| HTTP Framework | [Hono](https://hono.dev) (Bun-native) |
| BBS+ Signing / Verification | `@digitalbazaar/bbs-cryptosuite-2023` |
| JSON-LD Processing | `jsonld` (offline, no external HTTP) |
| `did:key` Resolution | `@digitalbazaar/did-method-key` |
| DataIntegrity Proofs | `@digitalbazaar/data-integrity` |
| Verifiable Credentials | `@digitalbazaar/vc` |
| Database | PostgreSQL via `postgres` npm |
| Input Validation | `zod` |
| Session Tokens | `jose` (JWT, 15-min TTL) |
| Key Encryption | AES-GCM (Web Crypto API, built into Bun) |
| Password Hashing | Bun built-in Argon2id (OWASP params) |

---

## API Endpoints

All endpoints are prefixed with `/v1`. Protected routes require `Authorization: Bearer <token>`.

### Email Auth (v1.2)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/auth/signup` | Public | Create account; auto-generates a `did:key` |
| `POST` | `/v1/auth/login` | Public | Exchange email + password for JWT |
| `POST` | `/v1/auth/forgot-password` | Public | Request a password reset token |
| `POST` | `/v1/auth/reset-password` | Public | Consume reset token, set new password |

### Users (v1.2)
| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/users/me` | Any role | Get your profile (includes org memberships) |
| `PATCH` | `/v1/users/me` | Any role | Update name or organizationName |

### Admin (v1.2)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/admin/users/:id/role` | `X-Admin-Secret` header | Upgrade a user's DID role |

### Organizations (v1.2)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/organizations` | Any role | Create an org with its own DID |
| `GET` | `/v1/organizations/:id` | Member | Get org details |
| `DELETE` | `/v1/organizations/:id` | Owner | Delete org and deactivate its DID |
| `GET` | `/v1/organizations/:id/members` | Member | List all org members |
| `POST` | `/v1/organizations/:id/invites` | Admin/Owner | Invite a user by email |
| `POST` | `/v1/organizations/invites/:token/accept` | Any role | Accept a pending invite |
| `PATCH` | `/v1/organizations/:id/members/:userId` | Admin/Owner | Change a member's org role |
| `DELETE` | `/v1/organizations/:id/members/:userId` | Admin/Owner or self | Remove a member (or leave) |

### DID Authentication (challenge-response path)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/auth/challenge` | Public | Request a one-time nonce for a DID |
| `POST` | `/v1/auth/verify` | Public | Submit signed nonce, receive JWT |

### DID Management
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/dids` | Public | Create a raw `did:key` (private key returned **once**) |
| `GET` | `/v1/dids/me` | Any role | Get your own DID document |
| `GET` | `/v1/dids/:did` | Public | Resolve any DID document |
| `DELETE` | `/v1/dids/:did` | Owner | Deactivate a DID |

### Verifiable Credentials
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/credentials/issue` | Issuer | Issue a BBS+-signed VC to a subject |
| `GET` | `/v1/credentials` | Issuer | List all issued VCs |
| `GET` | `/v1/credentials/:id` | Issuer / Subject | Fetch a VC by ID |
| `POST` | `/v1/credentials/:id/revoke` | Issuer | Revoke a credential |
| `GET` | `/v1/credentials/:id/status` | Public | Check credential status |

### Verifiable Presentations
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/presentations/derive` | Subject | Create a VP with BBS+ selective disclosure |
| `POST` | `/v1/presentations/verify` | Verifier | Verify a VP (proof + trust chain + revocation) |
| `GET` | `/v1/presentations/:id` | Subject | Fetch a previously derived presentation |

### Trust Registry
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/trust/attest` | Attester | Vouch for an issuer DID |
| `GET` | `/v1/trust/issuers` | Public | List all trusted issuers |
| `GET` | `/v1/trust/issuers/:did` | Public | Check if a DID is a trusted issuer |
| `POST` | `/v1/trust/attest/:id/revoke` | Attester | Revoke an issuer attestation |

---

## Core Flows

### 1. Account Setup & Role Assignment

```bash
# Create an account (did:key auto-generated, initial role = subject)
POST /v1/auth/signup
{ "email": "issuer@example.com", "password": "password123", "name": "Alice" }
→ { token, user: { id, did, role: "subject" } }

# Admin upgrades role (requires X-Admin-Secret header)
POST /v1/admin/users/<USER_ID>/role
{ "role": "issuer" }
→ { success: true }

# Log in again — JWT now carries role: "issuer"
POST /v1/auth/login
{ "email": "issuer@example.com", "password": "password123" }
→ { token }
```

### 2. Organization Setup

```bash
# Create an org with an institutional DID
POST /v1/organizations
{ "name": "Test University", "role": "issuer" }
→ { id, slug: "test-university", did: "did:key:z6Mk...", memberRole: "owner" }

# Invite an existing user to join the org (adds them immediately)
POST /v1/organizations/<ORG_ID>/invites
{ "email": "colleague@example.com", "role": "admin" }
→ { userId, memberRole: "admin" }

# Invite a new user (returns a token to share with them)
POST /v1/organizations/<ORG_ID>/invites
{ "email": "newperson@example.com", "role": "member" }
→ { inviteToken, expiresAt }

# New user accepts the invite after signing up
POST /v1/organizations/invites/<INVITE_TOKEN>/accept  {}
→ { success: true }
```

### 3. Trust Setup

```bash
# Attester authorizes the issuer (must use attester JWT)
POST /v1/trust/attest
{ "issuerDid": "did:key:z6Mk..." }
→ { id, issuerDid, attesterDid, createdAt }
```

### 4. Issuing a Verifiable Credential

```bash
# Issuer signs a VC with BBS+ (DataIntegrityProof)
POST /v1/credentials/issue
{
  "subjectDid": "did:key:...",
  "credentialType": ["UniversityDegree"],
  "claims": { "name": "Alice", "degree": "BSc Computer Science", "gpa": "3.9" }
}
→ signed VC with DataIntegrityProof  { id, proof, ... }
```

### 5. Selective Disclosure Presentation

```bash
# Subject reveals only name and degree — GPA stays hidden
POST /v1/presentations/derive
{ "credentialId": "urn:uuid:...", "revealedClaims": ["name", "degree"] }
→ VP with BBS+ derived proof

# Verifier checks the proof, trust chain, and revocation status
POST /v1/presentations/verify  { "presentation": <VP> }
→ { valid: true, disclosedClaims: { name, degree }, issuerTrusted: true, credentialStatus: "active" }
```

---

## Security

### OWASP API Security Top 10 Controls

| # | Threat | Control |
|---|---|---|
| API1 | Broken Object Level Authorization | Resource ownership enforced — callers can only access their own resources; org BOLA: invite email must match caller email |
| API2 | Broken Authentication | Single-use nonces (5-min TTL); short-lived JWTs (15-min); Argon2id passwords; timing-safe dummy hash on unknown-email login |
| API3 | Broken Object Property Level Authorization | Response serializers strip fields by role |
| API4 | Unrestricted Resource Consumption | Rate limiting: 100 req/min general, 10 req/min on sensitive endpoints; 64KB body cap |
| API5 | Broken Function Level Authorization | Role checked at middleware level before any handler; org role hierarchy (member < admin < owner) enforced per operation |
| API6 | Unsafe Business Flows | Issuance requires role + active trust attestation; last-owner removal blocked |
| API7 | SSRF | All JSON-LD contexts cached locally — zero outbound HTTP during request handling |
| API8 | Security Misconfiguration | CSP, HSTS, X-Frame-Options, X-Content-Type-Options on every response |
| API9 | Improper Inventory Management | All endpoints versioned under `/v1/` |
| API10 | Unsafe Input Consumption | Zod schemas on all inputs; JSON-LD `@context` allowlist |

### Additional Privacy Controls

- BBS+ selective disclosure — verifiers receive **only** the claims the subject chose to reveal
- Private keys stored AES-GCM encrypted; decrypted in-memory only during signing
- Private key returned only once at DID creation and never again
- Timing-safe Argon2id comparison on login — unknown-email and wrong-password return identical error and timing
- Append-only `audit_log` table records every issuance, revocation, verification, and auth event — claim values are never logged
- Password reset sessions invalidated immediately after a successful reset

---

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) >= 1.1
- PostgreSQL >= 14

### Setup

```bash
# Clone and install
git clone https://github.com/fparanso/did-zkp-api.git
cd did-zkp-api
bun install

# Configure environment
cp .env.example .env
# Edit .env — generate values for the required secrets:
openssl rand -hex 32    # → KEY_ENCRYPTION_SECRET
openssl rand -base64 32 # → JWT_SECRET
openssl rand -hex 32    # → ADMIN_SECRET

# Create the database
createdb did_zkp

# Start the server (runs migrations automatically on startup)
bun run dev
```

### Verify

```bash
curl http://localhost:3000/health
# → {"status":"ok"}
```

### Interactive API Docs

Open [http://localhost:3000/docs](http://localhost:3000/docs) for the Scalar UI with all endpoints, schemas, and try-it-out support.

### Running Tests

```bash
# Create test database
createdb did_zkp_test

# Unit tests
bun test:unit

# Integration tests
bun test:integration

# Security (OWASP) tests
bun test:security

# All tests
bun test
```

---

## CLI Utilities

### Signature Generator

For local development and testing, use the built-in CLI signature generator to create signatures for the DID challenge-response authentication. It retrieves the required nonce and private key from your local database, signs the challenge, and outputs the base64-encoded signature:

```bash
bun run generate-signature.ts <did> <challengeId>
```

Example:
```bash
bun run generate-signature.ts "did:key:z6MknwjrNSCBRBYdCgSXPHFQXNyisvEWM3SuVYnT6d215XUC" "af003fcc-5012-42f9-b508-4f7e4d88236a"
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `TEST_DATABASE_URL` | Tests | PostgreSQL connection string for test DB |
| `KEY_ENCRYPTION_SECRET` | Yes | 64-char hex string (32 bytes) for AES-GCM key encryption |
| `JWT_SECRET` | Yes | Secret for signing session JWTs |
| `ADMIN_SECRET` | Yes | Secret for `X-Admin-Secret` header on admin endpoints |
| `CORS_ORIGIN` | No | Allowed CORS origin (default: `http://localhost:3000`) |
| `PORT` | No | HTTP port (default: `3000`) |
| `NODE_ENV` | No | `development` or `production` |

---

## Database Schema

Eleven tables cover the full protocol lifecycle:

### Account & Identity
- **`users`** — email/password accounts, name, organizationName, FK → dids
- **`password_reset_tokens`** — one-time reset tokens with expiry and used flag
- **`dids`** — DID documents, Ed25519 + BLS12-381 encrypted key pairs, role
- **`sessions`** — JWT session records (15-min TTL)
- **`auth_challenges`** — single-use nonces for DID Auth (5-min TTL)

### Organizations
- **`organizations`** — org name, slug, DID, owner FK
- **`org_members`** — user ↔ org membership with role (`member`, `admin`, `owner`)
- **`org_invites`** — pending invites with email, token, expiry, and accepted flag

### Credentials & Trust
- **`credentials`** — signed VCs with BBS+ DataIntegrityProof
- **`presentations`** — derived VPs with selective-disclosure proofs
- **`trust_attestations`** — attestation VCs linking attesters to authorized issuers
- **`audit_log`** — append-only event log (UPDATE/DELETE blocked by DB trigger)

---

## Documentation

- [Design Spec](docs/superpowers/specs/2026-05-22-did-zkp-api-design.md) — architecture, data model, flows, security rationale
- [Implementation Plan](docs/superpowers/plans/2026-05-22-did-zkp-api.md) — 19-task TDD implementation guide
- [Interactive API Docs](http://localhost:3000/docs) — Scalar UI (server must be running)

---

## Standards & References

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [BBS Cryptosuite 2023](https://www.w3.org/TR/vc-di-bbs/)
- [Data Integrity 1.0](https://www.w3.org/TR/data-integrity/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
