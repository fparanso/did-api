# HAIP Migration Design — Phases 1, 2, 3

**Date:** 2026-05-26  
**Status:** Approved  
**Scope:** Migrate the DID-ZKP API from W3C VC 2.0 + BBS+ to OpenID4VC High Assurance Interoperability Profile (HAIP 1.0-final), in three independent phases.

---

## Context

The current stack (BBS+ / JSON-LD / custom REST) is a valid closed-ecosystem credential system but is incompatible with HAIP-conformant wallets, eIDAS 2.0, ISO 18013-5, and government identity ecosystems. The migration replaces the crypto and protocol surface while keeping the Hono framework, PostgreSQL, domain-driven layout, audit log, organizations, and user management intact.

Holder key custody (true SSI, where the wallet never exports private keys) is **out of scope** for these phases. The server remains custodial for now, which is acceptable for a back-office / demo deployment. Phase 4 (future) would introduce a real wallet client.

---

## Phase 1 — Replace Crypto Stack and Credential Format

### Goal
Issue and verify **SD-JWT VC** (`dc+sd-jwt`) signed with **ES256** (ECDSA P-256 + SHA-256), replacing W3C VC JSON-LD + BBS+. Existing REST endpoints keep their URL shape; only the credential wire format changes.

### What changes

**Remove (all `@digitalbazaar/*` libs and `jsonld`):**
- `@digitalbazaar/bbs-2023-cryptosuite`
- `@digitalbazaar/bls12-381-multikey`
- `@digitalbazaar/data-integrity`
- `@digitalbazaar/vc`
- `@digitalbazaar/ed25519-signature-2020`
- `@digitalbazaar/ed25519-verification-key-2020`
- `@digitalbazaar/did-method-key`
- `jsonld`
- `src/shared/jsonld/` (context loader + offline contexts)
- `src/shared/crypto/bbs.ts`

**Add:**
- `src/shared/crypto/p256.ts` — P-256 key generation via Web Crypto API (built into Bun, zero new deps)
- `src/shared/crypto/sd-jwt.ts` — SD-JWT VC issue, disclose, verify via `jose`

**Key generation** (`src/shared/crypto/did-key.ts`):
- Replace Ed25519 + BLS12-381 with a single P-256 ECDSA key pair
- `did:key` with P-256 multibase prefix `zDn...` (per did-key spec §2.6)
- DB: `bls_public_key` / `bls_private_key` columns dropped; Ed25519 columns repurposed as P-256 (`public_key`, `private_key` now store P-256 JWK JSON, AES-GCM encrypted)

**SD-JWT VC structure (issued credential):**
```
<header>.<payload>.<signature>~<disclosure_1>~<disclosure_2>~...
```

Header:
```json
{ "alg": "ES256", "typ": "dc+sd-jwt" }
```

Payload (non-selectively-disclosed claims are always present):
```json
{
  "iss": "did:key:zDn...",
  "sub": "did:key:zDn...",
  "iat": 1234567890,
  "exp": 1234567890,
  "vct": "UniversityDegree",
  "_sd_alg": "sha-256",
  "_sd": ["<hash_of_disclosure_1>", "<hash_of_disclosure_2>"],
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } }
}
```

Each disclosure (base64url-encoded JSON array):
```json
["<salt>", "<claim_name>", "<claim_value>"]
```

**Selective disclosure (replaces BBS+ derive):**
- `POST /v1/presentations/derive` accepts `revealedClaims: string[]`
- Server filters disclosures to only the revealed ones, appends a KB-JWT signed by the holder's P-256 key
- KB-JWT payload: `{ "nonce": "...", "aud": "verifier_did", "iat": ..., "sd_hash": "..." }`

**Verification (replaces BBS+ verify):**
- `POST /v1/presentations/verify` accepts the compact SD-JWT+KB-JWT string
- Validate ES256 issuer signature over the payload
- Validate KB-JWT signature using holder's `cnf.jwk`
- Validate `sd_hash` matches the disclosed claims
- Check issuer trust + credential status (unchanged)

**DB migration (006):**
```sql
ALTER TABLE dids DROP COLUMN bls_public_key;
ALTER TABLE dids DROP COLUMN bls_private_key;
-- public_key and private_key now store P-256 JWK (encrypted), comment updated

ALTER TABLE credentials ADD COLUMN sd_jwt TEXT;
-- sd_jwt stores the full compact SD-JWT string; document JSONB kept for audit
```

**No new dependencies.** Uses only `jose` (already installed) + Bun's built-in Web Crypto.

---

## Phase 2 — Add OID4VCI Issuance Protocol

### Goal
Expose a wallet-facing credential issuance surface following OID4VCI (authorization code flow + PKCE + DPoP). The existing `POST /v1/credentials/issue` endpoint is kept as an admin/internal path; OID4VCI is a new parallel surface.

### New endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-credential-issuer` | Issuer metadata (credential types, algorithms, endpoints) |
| `POST` | `/oauth/par` | Pushed Authorization Request — wallet submits auth params, receives `request_uri` |
| `GET` | `/oauth/authorize` | Authorization endpoint — validates PAR, redirects with auth code |
| `POST` | `/oauth/token` | Token endpoint — PKCE code exchange, DPoP validation, issues access token |
| `POST` | `/oauth/nonce` | Nonce endpoint — returns `c_nonce` for holder key proof |
| `POST` | `/oauth/credentials` | Credential endpoint — validates DPoP + key proof, issues SD-JWT VC |

### Flow

```
Wallet                          Issuer API
  │                                 │
  │─── GET /.well-known/... ───────>│  discover metadata
  │<── 200 metadata ────────────────│
  │                                 │
  │─── POST /oauth/par ────────────>│  PAR (scope, redirect_uri, PKCE, wallet_attestation)
  │<── 201 { request_uri } ─────────│
  │                                 │
  │─── GET /oauth/authorize ───────>│  (browser redirect)
  │<── 302 redirect with code ──────│
  │                                 │
  │─── POST /oauth/token ──────────>│  code + code_verifier + DPoP header
  │<── 200 { access_token } ────────│  DPoP-bound access token
  │                                 │
  │─── POST /oauth/nonce ──────────>│  (optional, get fresh c_nonce)
  │<── 200 { c_nonce } ─────────────│
  │                                 │
  │─── POST /oauth/credentials ────>│  Bearer + DPoP + proof JWT (key binding)
  │<── 200 { credential } ──────────│  compact SD-JWT VC
```

### Key constraints
- PKCE `S256` method only (no plain)
- DPoP (RFC 9449): server issues `DPoP-Nonce` header, validates DPoP proof on token + credential requests
- Wallet attestation: client authenticates at `/oauth/par` and `/oauth/token` using a signed JWT in `client_assertion` (simplified — full X.509 wallet attestation is Phase 4)
- Key proof: wallet sends a `proof` object with `proof_type: "jwt"` containing a signed JWT with the wallet's public key and the `c_nonce`
- `cnf` claim in issued SD-JWT VC is derived from the key proof's public key

### New DB table
```sql
CREATE TABLE oauth_par_requests (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_uri    TEXT NOT NULL UNIQUE,
  client_id      TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  scope          TEXT NOT NULL,
  expires_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE oauth_auth_codes (
  code           TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope          TEXT NOT NULL,
  did            TEXT REFERENCES dids(id),
  expires_at     TIMESTAMPTZ NOT NULL,
  used           BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE oauth_dpop_nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL
);
```

### Issuer metadata shape (`/.well-known/openid-credential-issuer`)
```json
{
  "credential_issuer": "https://<host>",
  "credential_endpoint": "https://<host>/oauth/credentials",
  "nonce_endpoint": "https://<host>/oauth/nonce",
  "authorization_servers": ["https://<host>"],
  "credential_configurations_supported": {
    "UniversityDegree": {
      "format": "dc+sd-jwt",
      "vct": "UniversityDegree",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"]
    }
  }
}
```

---

## Phase 3 — Add OID4VP Presentation Protocol

### Goal
Expose a wallet-facing presentation verification surface following OID4VP (verifier-initiated, `direct_post` response mode). The existing `POST /v1/presentations/verify` is kept for internal/admin use.

### New endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/oauth/vp/initiate` | Verifier creates a VP session — receives `request_uri` + QR payload |
| `GET` | `/oauth/request/{id}` | Signed request object (JAR) — wallet fetches via `request_uri` |
| `POST` | `/oauth/direct_post` | Wallet POSTs `vp_token` (compact SD-JWT+KB-JWT) |
| `GET` | `/oauth/vp-result/{id}` | Verifier polls for result after wallet posts |

### Flow

```
Verifier                        API (AS/RP)              Wallet
  │                                 │                       │
  │─── POST /oauth/vp/initiate ────>│                       │  verifier creates VP session
  │<── { request_uri, session_id } ─│                       │
  │     (show as QR / deep link)    │                       │
  │                                 │                       │
  │                                 │<── GET /request/{id} ─│  wallet fetches signed request
  │                                 │─── signed req obj ───>│  (JAR with DCQL query + nonce)
  │                                 │                       │
  │                                 │<── POST /direct_post ─│  vp_token (SD-JWT+KB-JWT)
  │                                 │─── 200 OK ───────────>│
  │                                 │                       │
  │─── GET /vp-result/{session_id} >│
  │<── { valid, disclosed_claims } ─│
```

### Request object (JAR, signed ES256)
```json
{
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "response_uri": "https://<host>/oauth/direct_post",
  "nonce": "<random>",
  "dcql_query": {
    "credentials": [{
      "id": "cred1",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["UniversityDegree"] },
      "claims": [{ "path": ["name"] }, { "path": ["degree"] }]
    }]
  }
}
```

### Verification steps at `POST /direct_post`
1. Parse compact SD-JWT+KB-JWT string
2. Validate ES256 issuer signature on SD-JWT payload
3. Validate `_sd` hashes match provided disclosures
4. Validate KB-JWT: signature matches `cnf.jwk` from SD-JWT payload
5. Validate KB-JWT `nonce` matches session nonce, `aud` matches `response_uri`, `sd_hash` matches disclosed set
6. Check issuer trust (trust registry lookup, same as current)
7. Check Token Status List (if `status` claim present) or fall back to DB status check
8. Store result, notify verifier

### New DB table
```sql
CREATE TABLE vp_sessions (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce          TEXT NOT NULL UNIQUE,
  verifier_did   TEXT,
  dcql_query     JSONB NOT NULL,
  status         TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','complete','failed')),
  result         JSONB,
  expires_at     TIMESTAMPTZ NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Token Status List (add in Phase 1, used in Phase 3)

A signed JWT bitmap allowing verifiers to check revocation without calling back per-credential.

**New endpoint:** `GET /status/{listId}` — returns a signed `application/statuslist+jwt`

**DB change:**
```sql
ALTER TABLE credentials ADD COLUMN status_list_id    TEXT DEFAULT 'default';
ALTER TABLE credentials ADD COLUMN status_list_index INT;
```

Each credential is assigned a unique, random index in the list at issuance. The bitmap is regenerated on every revocation.

---

## What is NOT in scope (Phase 4+)

- X.509 certificate trust chains (`x5c` JOSE header, CA infrastructure)
- OpenID Federation 1.0 trust chains
- `mso_mdoc` / ISO 18013-5 credential format
- True holder key custody (wallet client with secure enclave)
- Response encryption (JWE ECDH-ES) on OID4VP responses
- Full wallet attestation with hardware-backed X.509 chain

---

## Dependency changes

**Remove:**
```
@digitalbazaar/bbs-2023-cryptosuite
@digitalbazaar/bls12-381-multikey
@digitalbazaar/data-integrity
@digitalbazaar/vc
@digitalbazaar/ed25519-signature-2020
@digitalbazaar/ed25519-verification-key-2020
@digitalbazaar/did-method-key
jsonld
```

**Keep (already installed):**
```
jose  ← ES256 sign/verify, JWT, JWK operations
hono  ← unchanged
zod   ← unchanged
postgres ← unchanged
```

**Add:**
```
(none) — all new crypto uses jose + Bun Web Crypto API
```

---

## File layout changes

```
src/
  shared/
    crypto/
      p256.ts          NEW — P-256 key gen, did:key, JWK helpers
      sd-jwt.ts        NEW — SD-JWT issue, disclose, verify
      keys.ts          KEEP — AES-GCM key encryption (unchanged)
      bbs.ts           DELETE
      did-key.ts       REPLACE (now uses p256.ts)
    jsonld/            DELETE entire directory
  domains/
    credentials/
      service.ts       REPLACE issueCredential → SD-JWT
    presentation/
      service.ts       REPLACE deriveSelectivePresentation + verifyVp → SD-JWT
    oauth/             NEW domain
      routes.ts        OID4VCI + OID4VP endpoints
      service.ts       PAR, token, credential, direct_post logic
      repository.ts    oauth_par_requests, oauth_auth_codes, vp_sessions
  migrations/
    006_haip_p1.sql    DROP bls columns, ADD sd_jwt + status_list columns
    007_haip_p2.sql    ADD oauth_par_requests, oauth_auth_codes, oauth_dpop_nonces
    008_haip_p3.sql    ADD vp_sessions
```
