# DID + ZKP REST API — Design Spec
**Date:** 2026-05-22  
**Status:** Approved  
**Stack:** Bun · PostgreSQL · BBS+ (bbs-2023) · did:key · W3C VC Data Model 2.0

---

## 1. Overview

A REST API that implements the W3C Decentralized Identity (DID) protocol and Zero-Knowledge Proofs via BBS+ signatures for selective disclosure of Verifiable Credentials (VCs). The system covers four actor roles: **subject** (holder), **issuer**, **verifier**, and **attester** (trust registry authority).

---

## 2. Architecture

**Pattern:** Domain-Driven Modular — one Bun HTTP server organized by protocol domain. Each domain owns its routes, services, and DB queries. Shared crypto and DB utilities are injected via explicit imports.

### Project Structure

```
did-zkp/
├── src/
│   ├── domains/
│   │   ├── did/
│   │   │   ├── routes.ts        # GET /v1/dids, POST /v1/dids, GET /v1/dids/:did
│   │   │   ├── service.ts       # DID generation, resolution, key export
│   │   │   └── repository.ts   # DID document CRUD in Postgres
│   │   ├── credentials/
│   │   │   ├── routes.ts        # POST /v1/credentials/issue, GET, revoke
│   │   │   ├── service.ts       # VC construction, BBS+ signing, status list
│   │   │   └── repository.ts
│   │   ├── presentation/
│   │   │   ├── routes.ts        # POST /v1/presentations/derive, /verify
│   │   │   ├── service.ts       # BBS+ selective disclosure, VP envelope, proof check
│   │   │   └── repository.ts
│   │   ├── trust/
│   │   │   ├── routes.ts        # POST /v1/trust/attest, GET /v1/trust/issuers
│   │   │   ├── service.ts       # Attestation VC issuance, trust chain resolution
│   │   │   └── repository.ts
│   │   └── auth/
│   │       ├── routes.ts        # POST /v1/auth/challenge, POST /v1/auth/verify
│   │       ├── service.ts       # Challenge generation, DID Auth proof verification
│   │       └── middleware.ts    # JWT session middleware for protected routes
│   ├── shared/
│   │   ├── crypto/
│   │   │   ├── bbs.ts           # BBS+ sign / deriveProof / verifyProof wrappers
│   │   │   └── did-key.ts       # did:key generation, DID document construction
│   │   ├── jsonld/
│   │   │   └── loader.ts        # Offline JSON-LD context loader (no external HTTP)
│   │   ├── db.ts                # Postgres pool + migration runner
│   │   └── errors.ts            # Typed HTTP error classes
│   ├── migrations/              # SQL files: 001_init.sql, 002_audit.sql, etc.
│   └── index.ts                 # Server entry point, route mounting
├── tests/
│   ├── fixtures/
│   │   ├── issuer-did.json
│   │   ├── subject-did.json
│   │   ├── attester-did.json
│   │   ├── sample-vc.json
│   │   └── sample-vp.json
│   ├── unit/
│   ├── integration/
│   └── security/
├── docs/
├── package.json
└── bunfig.toml
```

### Key Libraries

| Concern | Library |
|---|---|
| BBS+ signing / verification | `@digitalbazaar/bbs-cryptosuite-2023` |
| JSON-LD processing | `jsonld` (with offline context caching) |
| `did:key` resolution | `@digitalbazaar/did-method-key` |
| DataIntegrity proofs | `@digitalbazaar/data-integrity` |
| Postgres | `postgres` (npm, Bun-compatible) |
| Input validation | `zod` |
| Session tokens | `jose` (short-lived JWTs, 15 min) |

---

## 3. Data Model

### 3.1 Tables

```sql
-- DID documents for all actors
CREATE TABLE dids (
  id          TEXT PRIMARY KEY,        -- did:key:z6Mk...
  role        TEXT NOT NULL,           -- 'subject' | 'issuer' | 'verifier' | 'attester'
  document    JSONB NOT NULL,          -- full W3C DID document
  public_key  TEXT NOT NULL,           -- BLS12-381 G2 public key (multibase)
  private_key TEXT NOT NULL,           -- AES-GCM encrypted private key
  created_at  TIMESTAMPTZ DEFAULT now()
);

-- Issued Verifiable Credentials
CREATE TABLE credentials (
  id           TEXT PRIMARY KEY,       -- VC URI
  issuer_did   TEXT REFERENCES dids(id),
  subject_did  TEXT REFERENCES dids(id),
  type         TEXT[] NOT NULL,        -- e.g. ['VerifiableCredential','UniversityDegree']
  claims       JSONB NOT NULL,         -- credentialSubject claims
  document     JSONB NOT NULL,         -- full signed VC (with DataIntegrityProof)
  status       TEXT DEFAULT 'active',  -- 'active' | 'revoked'
  issued_at    TIMESTAMPTZ DEFAULT now(),
  expires_at   TIMESTAMPTZ
);

-- Verifiable Presentations (selective disclosure results)
CREATE TABLE presentations (
  id               TEXT PRIMARY KEY,
  holder_did       TEXT REFERENCES dids(id),
  credential_ids   TEXT[],
  document         JSONB NOT NULL,     -- full VP with derived BBS+ proof
  disclosed_claims JSONB NOT NULL,     -- only the revealed claim keys
  created_at       TIMESTAMPTZ DEFAULT now()
);

-- Attestation credentials (attester vouches for issuer authority)
CREATE TABLE trust_attestations (
  id             TEXT PRIMARY KEY,
  attester_did   TEXT REFERENCES dids(id),
  issuer_did     TEXT REFERENCES dids(id),
  credential     JSONB NOT NULL,       -- attestation VC document
  status         TEXT DEFAULT 'active',-- 'active' | 'revoked'
  issued_at      TIMESTAMPTZ DEFAULT now(),
  expires_at     TIMESTAMPTZ
);

-- DID Auth challenge/response sessions
CREATE TABLE auth_challenges (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did          TEXT NOT NULL,
  nonce        TEXT NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,   -- 5-minute TTL
  used         BOOLEAN DEFAULT false
);

-- API sessions (post DID Auth)
CREATE TABLE sessions (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did        TEXT NOT NULL,
  role       TEXT NOT NULL,
  token      TEXT NOT NULL,            -- JWT
  expires_at TIMESTAMPTZ NOT NULL      -- 15-minute TTL
);

-- Append-only audit trail
CREATE TABLE audit_log (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_did  TEXT NOT NULL,
  action     TEXT NOT NULL,            -- 'issue' | 'revoke' | 'verify' | 'attest' | 'auth'
  target_id  TEXT,
  result     TEXT NOT NULL,            -- 'success' | 'failure'
  created_at TIMESTAMPTZ DEFAULT now()
);
```

### 3.2 Private Key Storage

Private keys are encrypted with AES-GCM using `KEY_ENCRYPTION_SECRET` from the environment. Keys are decrypted in-memory only during signing operations and never logged or returned after initial creation.

---

## 4. API Endpoints

All endpoints are prefixed with `/v1`. Protected routes require `Authorization: Bearer <jwt>`.

### Auth — Public
| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/auth/challenge` | Request a one-time nonce for a given DID |
| `POST` | `/v1/auth/verify` | Submit signed nonce, receive session JWT |

### DID Management
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/dids` | Public | Generate `did:key` keypair + DID document; returns private key **once** |
| `GET` | `/v1/dids/me` | Any role | Get caller's own DID document *(must be registered before `/:did` in the router)* |
| `GET` | `/v1/dids/:did` | Public | Resolve a DID document |
| `DELETE` | `/v1/dids/:did` | Owner | Deactivate (soft-delete) a DID |

### Credentials — Issuer only (write), Owner (read)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/credentials/issue` | Issuer | Issue a BBS+ signed VC to a subject |
| `GET` | `/v1/credentials/:id` | Issuer or Subject (owner) | Fetch VC by ID |
| `GET` | `/v1/credentials` | Issuer | List all VCs issued by caller |
| `POST` | `/v1/credentials/:id/revoke` | Issuer | Revoke a credential |
| `GET` | `/v1/credentials/:id/status` | Public | Check active/revoked status |

### Presentations — Subject (write), Verifier (verify)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/presentations/derive` | Subject | Create VP with BBS+ selective disclosure |
| `POST` | `/v1/presentations/verify` | Verifier | Verify VP — checks proof, trust chain, revocation |
| `GET` | `/v1/presentations/:id` | Subject (owner) | Fetch a previously derived presentation |

### Trust Registry — Attester (write), Public (read)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/trust/attest` | Attester | Issue attestation VC vouching for an issuer DID |
| `GET` | `/v1/trust/issuers` | Public | List all attested (trusted) issuers |
| `GET` | `/v1/trust/issuers/:did` | Public | Check whether a specific issuer DID is attested |
| `POST` | `/v1/trust/attest/:id/revoke` | Attester | Revoke an attestation |

**Total: 18 endpoints**

---

## 5. Core Data Flows

### Flow 1 — VC Issuance
```
Issuer → POST /v1/credentials/issue { subjectDid, credentialType, claims, expiresAt }

1. Resolve subject DID → validate exists
2. Check issuer has active trust attestation
3. Build W3C VC 2.0 JSON-LD document
4. Decrypt issuer private key in memory → BBS+ sign → DataIntegrityProof embedded
5. Store VC → write audit log → return signed VC
```

### Flow 2 — Selective Disclosure VP Derivation
```
Subject → POST /v1/presentations/derive { credentialId, revealedClaims: ['name','degree'] }

1. Fetch full VC from DB (all claims + BBS+ signature)
2. BBS+ deriveProof: input full VC + issuer public key + original BBS+ signature
   + indices of disclosed claims → derived proof (no subject private key needed here)
3. Wrap derived proof in W3C VP envelope
4. Decrypt subject private key in memory → sign VP envelope (holder-binding proof)
   proving the subject is the legitimate holder
5. Store VP → write audit log → return VP to subject
```

### Flow 3 — VP Verification
```
Verifier → POST /v1/presentations/verify { presentation: <VP document> }

1. Extract issuer DID → resolve DID document → get BLS12-381 public key
2. Check issuer DID in trust registry (active attestation?)
3. Check credential status (not revoked?)
4. BBS+ verifyProof: derived proof + disclosed claims + issuer public key
5. Write audit log → return { valid, disclosedClaims, issuerTrusted, credentialStatus }
```

### JSON-LD Context Loading
All contexts (`bbs-2023`, W3C VC 2.0, security vocab) are cached locally at server startup. Zero outbound HTTP during request handling — prevents SSRF and timing-dependent failures.

---

## 6. Security & OWASP API Security Top 10

| # | Threat | Mitigation |
|---|---|---|
| API1 | Broken Object Level Authorization | Resource ownership enforced by middleware — caller DID must match resource owner DID |
| API2 | Broken Authentication | Single-use nonces (5 min TTL), marked `used=true` immediately; JWTs expire in 15 min |
| API3 | Broken Object Property Level Authorization | Response serializers strip fields by role — verifiers see `disclosedClaims` only |
| API4 | Unrestricted Resource Consumption | Rate limiting: 100 req/min general, 10 req/min on `/auth/*` and `/credentials/issue`; body size capped at 64KB |
| API5 | Broken Function Level Authorization | Role checked at middleware level before any handler runs; returns `403 UNAUTHORIZED_ROLE` |
| API6 | Unrestricted Access to Sensitive Business Flows | Issuance and attestation require valid role + active trust chain; no bulk endpoints |
| API7 | SSRF | All JSON-LD contexts loaded from local cache; DID resolution is DB-only, no external resolvers |
| API8 | Security Misconfiguration | Security headers on every response (CSP, HSTS, X-Content-Type-Options, X-Frame-Options); CORS allowlist; no debug info in prod errors |
| API9 | Improper Inventory Management | All endpoints versioned under `/v1/`; no shadow endpoints |
| API10 | Unsafe Consumption of APIs | Zod schemas validate all inputs; JSON-LD `@context` allowlist rejects unknown contexts |

### Additional Privacy Controls
- BBS+ selective disclosure — verifiers receive only the claims the subject chose to reveal; server never logs claim values
- Private key returned only once at DID creation; server stores AES-GCM encrypted copy
- Append-only `audit_log` records actor, action, and result — never claim values
- No stack traces, internal paths, or key material in error responses

---

## 7. Error Handling

### Response Shape
```json
{
  "error": "CREDENTIAL_REVOKED",
  "message": "The credential has been revoked",
  "status": 422
}
```

### Error Codes
| Code | HTTP | Scenario |
|---|---|---|
| `DID_NOT_FOUND` | 404 | DID has no registered document |
| `INVALID_PROOF` | 422 | BBS+ proof verification failed |
| `CREDENTIAL_REVOKED` | 422 | VC or attestation has been revoked |
| `ISSUER_NOT_TRUSTED` | 403 | Issuer has no active attestation |
| `CHALLENGE_EXPIRED` | 401 | Nonce expired or already used |
| `UNAUTHORIZED_ROLE` | 403 | Caller's role cannot access this endpoint |
| `INVALID_DISCLOSURE` | 422 | Requested claims don't exist in the credential |
| `INVALID_CONTEXT` | 422 | Unknown JSON-LD `@context` value |
| `RATE_LIMITED` | 429 | Caller exceeded request rate limit |

---

## 8. Testing Strategy

**Test runner:** `bun test` (built-in, no Jest required)

### Unit Tests
- `shared/crypto/bbs.ts` — sign, deriveProof, verifyProof with known fixtures
- `shared/crypto/did-key.ts` — DID generation, document shape, multibase encoding
- `shared/jsonld/loader.ts` — context loading, unknown context rejection
- Error classes and role-check middleware logic

### Integration Tests (real Postgres: `did_zkp_test` DB)
- Full lifecycle: register issuer → attest → register subject → issue VC → derive VP → verify VP
- Revocation path: issue → revoke → verify returns `credentialStatus: revoked`
- Trust path: verify fails without attestation; passes after attestation issued
- DID Auth flow: challenge → sign → verify → use token → token expiry

### Security Tests
- Replay used nonce → `CHALLENGE_EXPIRED`
- Tampered claim in VP → `INVALID_PROOF`
- Issuer-only endpoint called as subject → `UNAUTHORIZED_ROLE`
- Unknown `@context` injected → `422 INVALID_CONTEXT`
- Rate limit exceeded → `429 RATE_LIMITED`
- Access another subject's credential by ID → `403`

---

## 9. Environment Variables

```env
DATABASE_URL=postgresql://user:pass@localhost:5432/did_zkp
KEY_ENCRYPTION_SECRET=<32-byte hex>   # AES-GCM key for private key encryption
JWT_SECRET=<random string>            # JWT signing secret
CORS_ORIGIN=http://localhost:3000     # Allowed origin(s)
NODE_ENV=development                  # 'development' | 'production'
```
