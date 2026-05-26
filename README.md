# DID + HAIP REST API

A production-ready identity API aligned with the **OpenID4VC High Assurance Interoperability Profile 1.0 (HAIP)**. Issue, share, and verify tamper-proof digital credentials using **SD-JWT VC** (`dc+sd-jwt`) and **ISO 18013-5 mso_mdoc** — the same formats used in government digital ID programmes, EUDI wallets, and mobile driver's licences.

All cryptography is **P-256 / ES256** throughout — no external crypto libraries, no BLS, no JSON-LD. Built on Bun + Hono + PostgreSQL.

---

## Standards Alignment

| Standard | Role in this API |
|---|---|
| [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html) | Top-level interoperability profile — mandates P-256, SD-JWT VC, DPoP, PKCE |
| [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) | Every actor gets a `did:key` (P-256 multikey) — globally unique, self-sovereign |
| [SD-JWT VC (`dc+sd-jwt`)](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html) | Credential format with per-claim salted hashes for selective disclosure |
| [ISO 18013-5 mso_mdoc](https://www.iso.org/standard/69084.html) | CBOR/COSE credential format used by mobile driver's licences and EUDI |
| [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) | Authorization-code issuance flow: PAR + PKCE + DPoP + key proof JWT |
| [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | Verifier-initiated presentation flow: signed JAR + KB-JWT holder binding |
| [Token Status List 1.0](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html) | Compact bitmap revocation registry signed as a JWT |
| [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449) | Demonstration of Proof of Possession — key-bound access tokens |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | Security controls on every endpoint |

---

## Actors & Roles

| Role | Responsibility |
|---|---|
| **Attester** | Trust anchor — vouches for which issuers may sign credentials |
| **Issuer** | Signs SD-JWT VC + mso_mdoc credentials for subjects (requires active trust attestation) |
| **Subject / Wallet** | Holds credentials; derives selective-disclosure presentations |
| **Verifier** | Validates presentations against cryptographic proof, trust chain, and revocation |
| **Admin** | Upgrades account roles via server-side secret |

---

## How It Works — Concept Overview

```mermaid
flowchart LR
    subgraph Identity["🔑 Identity Layer"]
        DID["did:key\n(P-256 keypair)"]
        DOC["DID Document\n(Multikey · publicKeyJwk)"]
        DID -->|resolves to| DOC
    end

    subgraph Issuance["📜 Credential Issuance"]
        VC_SDJWT["SD-JWT VC\n(dc+sd-jwt)\nES256 signed"]
        VC_MDOC["mso_mdoc\n(ISO 18013-5)\nCOSE_Sign1"]
        HOLDER["Holder Key\n(P-256 JWK)\ncnf.jwk binding"]
        SLIST["Token Status List\nbitmap · signed JWT"]
    end

    subgraph Presentation["🔍 Selective Disclosure"]
        DISC["Selected Disclosures\n(salted claim hashes)"]
        KB["KB-JWT\n(holder-signed)\nnonce · sd_hash"]
        VP["SD-JWT VP\nissuerJwt~disc1~disc2~kbJwt"]
    end

    subgraph Verification["✅ Verification"]
        SIG["Issuer P-256\nsignature check"]
        HASH["Disclosure hash\nverification"]
        TRUST["Trust registry\ncheck"]
        REVOKE["Status List\nrevocation check"]
    end

    DID --> VC_SDJWT
    DID --> VC_MDOC
    HOLDER --> KB
    VC_SDJWT --> DISC
    DISC --> VP
    KB --> VP
    VP --> SIG & HASH & TRUST & REVOKE

    style Identity fill:#dce8ff,stroke:#4a90d9
    style Issuance fill:#dcffe8,stroke:#27ae60
    style Presentation fill:#f5dcff,stroke:#8e44ad
    style Verification fill:#fff3dc,stroke:#e6a817
```

---

## Part 1 — Identity Creation

### 1-A. Generating a DID (P-256 `did:key`)

Every actor — human or machine — starts by generating a `did:key` identity backed by a **P-256 keypair**. The DID is derived deterministically from the compressed public key using a multicodec prefix.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client / Wallet
    participant API as DID + HAIP API
    participant DB as PostgreSQL

    Note over C,API: POST /v1/dids  { role: "subject" }

    C->>API: Create DID request

    rect rgb(220, 235, 255)
        Note over API: Key Generation (Web Crypto API)
        API->>API: crypto.subtle.generateKey(P-256, extractable)
        API->>API: Export publicKeyJwk + privateKeyJwk
        API->>API: Compress public key → 33 bytes (x coord + sign bit)
        API->>API: Prepend multicodec [0x80, 0x24] → 35 bytes
        API->>API: base58btc encode → zDnae...
        API->>API: did = "did:key:zDnae..."
    end

    rect rgb(220, 255, 230)
        Note over API: Build DID Document
        API->>API: verificationMethod: { type: Multikey, publicKeyJwk }
        API->>API: authentication + assertionMethod arrays
    end

    rect rgb(255, 243, 220)
        Note over API,DB: Persist
        API->>API: AES-GCM encrypt(privateKeyJwk) → encryptedPrivateKey
        API->>DB: INSERT dids (id, role, document, publicKey, encryptedPrivateKey)
    end

    API-->>C: { did, document, privateKey: JWK } ← private key returned ONCE only

    Note over C: ⚠️ Client must store the privateKey JWK securely.<br/>The server never stores the raw private key.
```

**What you get back:**
```json
{
  "did": "did:key:zDnaeWJjH...",
  "role": "subject",
  "document": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:key:zDnaeWJjH...",
    "verificationMethod": [{
      "type": "Multikey",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }]
  },
  "privateKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..." }
}
```

---

### 1-B. Authenticating with Your DID (P-256 Challenge-Response)

Once you have a DID, you authenticate using a **cryptographic challenge-response** — no password required.

```mermaid
sequenceDiagram
    autonumber
    participant W as Wallet / Client
    participant API as DID + HAIP API
    participant DB as PostgreSQL

    W->>API: POST /v1/auth/challenge { did }
    API->>DB: Look up DID → fetch publicKeyJwk
    API->>DB: INSERT auth_challenges (challengeId, nonce, expiresIn: 5min)
    API-->>W: { challengeId, nonce }

    rect rgb(220, 235, 255)
        Note over W: Sign the challenge (Web Crypto API)
        W->>W: message = UTF8(did + ":" + nonce)
        W->>W: sigDer = crypto.subtle.sign({ name:"ECDSA", hash:"SHA-256" }, privateKey, message)
        W->>W: signature = base64(sigDer)
    end

    W->>API: POST /v1/auth/verify { did, challengeId, signature }

    rect rgb(220, 255, 230)
        Note over API: Verification
        API->>DB: Fetch challenge by challengeId (must be unused, within TTL)
        API->>DB: Mark challenge as used (nonce replay prevention)
        API->>DB: Fetch publicKeyJwk for DID
        API->>API: crypto.subtle.verify(ECDSA/SHA-256, publicKey, sigDer, message)
    end

    API-->>W: { token: "eyJhbGci..." } ← 15-minute JWT Bearer token

    Note over W: Use token as Authorization: Bearer <token> on all protected endpoints
```

---

## Part 2 — Credential Issuance (Direct REST API)

### 2-A. Trust Setup — Authorising an Issuer

Before an issuer can sign credentials, an **attester** must vouch for them in the trust registry.

```mermaid
sequenceDiagram
    autonumber
    actor AD as 🛡️ Admin
    actor AT as 🔐 Attester
    actor IS as 🏛️ Issuer
    participant API as DID + HAIP API

    Note over AD,IS: Role assignment (one-time setup)

    AD->>API: POST /v1/admin/users/{issuerId}/role { role:"issuer" }
    API-->>AD: { success: true }

    AD->>API: POST /v1/admin/users/{attesterId}/role { role:"attester" }
    API-->>AD: { success: true }

    Note over AT: Attester logs in with their newly assigned role
    AT->>API: POST /v1/auth/login { email, password }
    API-->>AT: { token }  ← JWT carries role:"attester"

    AT->>API: POST /v1/trust/attest { issuerDid: "did:key:zDnae..." }
    Note over API: Persists trust_attestation record<br/>Issuer is now in the active trust registry
    API-->>AT: { id, issuerDid, attesterDid, createdAt }

    Note over IS: Verifier can check any time
    IS->>API: GET /v1/trust/issuers/{issuerDid}
    API-->>IS: { trusted: true }
```

---

### 2-B. Issuing an SD-JWT VC + mso_mdoc Credential

```mermaid
sequenceDiagram
    autonumber
    actor IS as 🏛️ Issuer
    actor SU as 👤 Subject
    participant API as DID + HAIP API
    participant DB as PostgreSQL

    IS->>API: POST /v1/credentials/issue<br/>{ subjectDid, credentialType, claims }

    rect rgb(220, 235, 255)
        Note over API: Pre-flight checks
        API->>DB: Verify issuer has ACTIVE trust attestation
        API->>DB: Verify subjectDid exists and is active
    end

    rect rgb(220, 255, 230)
        Note over API: SD-JWT VC construction (dc+sd-jwt)
        API->>API: Generate ephemeral holder P-256 keypair
        API->>API: For each claim → salt = randomBytes(16) → disclosure = [salt, key, value]
        API->>API: _sd[i] = BASE64URL(SHA-256(JSON(disclosure_i)))
        API->>API: Build JWT payload: { iss, sub, iat, exp, cnf:{jwk}, _sd, vct }
        API->>API: Sign JWT header.payload with issuer P-256 key (ES256)
        API->>API: sdJwt = header.payload.sig~disc1~disc2~...~
    end

    rect rgb(255, 243, 220)
        Note over API: mso_mdoc construction (ISO 18013-5)
        API->>API: Build IssuerNameSpaces: { namespace: [[random, claimKey, claimValue], ...] }
        API->>API: Build MSO: { docType, valueDigests, validityInfo }
        API->>API: COSE_Sign1 = [protected, unprotected, MSO_CBOR, signature]
        API->>API: Sign COSE_Sign1 with issuer P-256 key (ES256)
        API->>API: mdoc = BASE64URL(CBOR(IssuerSigned))
    end

    rect rgb(245, 220, 255)
        Note over API: Token Status List assignment
        API->>DB: SELECT NEXTVAL('credential_status_idx_seq') → statusListIndex
        API->>DB: INSERT credentials (sdJwt, mdoc, holderKey, statusListId, statusListIndex)
    end

    API-->>IS: { id, sdJwt, mdoc, holderKey: { privateKeyJwk }, proof }

    Note over IS,SU: Issuer delivers credentialId + sdJwt to Subject out-of-band
    SU->>API: GET /v1/credentials/{id}
    API-->>SU: Full credential record (issuer or subject only)
```

**What the SD-JWT VC looks like internally:**

```mermaid
block-beta
  columns 3

  block:header["JWT Header"]:1
    H["{ alg: ES256\n typ: dc+sd-jwt }"]
  end

  block:payload["JWT Payload"]:1
    P["{ iss: did:key:zDnae...\n sub: did:key:zDnae...\n vct: UniversityDegree\n cnf: { jwk: holderPublicKey }\n _sd: [ hash1, hash2, hash3 ] }"]
  end

  block:sig["Issuer Signature"]:1
    S["ES256\nP-256/SHA-256"]
  end

  block:discs["Selective Disclosures"]:3
    D1["~[salt1, name, Alice Smith]~"]
    D2["~[salt2, degree, BSc Computer Science]~"]
    D3["~[salt3, gpa, 3.9]~"]
  end

  style header fill:#dce8ff,stroke:#4a90d9
  style payload fill:#dcffe8,stroke:#27ae60
  style sig fill:#fff3dc,stroke:#e6a817
  style discs fill:#f5dcff,stroke:#8e44ad
```

---

## Part 3 — Selective Disclosure & Verification

### 3-A. Subject Derives a Selective-Disclosure Presentation

```mermaid
sequenceDiagram
    autonumber
    actor SU as 👤 Subject / Wallet
    actor VE as 🔍 Verifier
    participant API as DID + HAIP API

    Note over SU: Credential: { name, degree, gpa, nationality }
    Note over SU: Subject decides to reveal only: name + degree

    SU->>API: POST /v1/presentations/derive<br/>{ credentialId, revealedClaims: ["name","degree"] }

    rect rgb(220, 235, 255)
        Note over API: SD-JWT selective filtering
        API->>API: Parse full SD-JWT: issuerJwt~disc1~disc2~disc3~disc4~
        API->>API: Filter — keep only disclosures matching revealedClaims
        API->>API: partialSdJwt = issuerJwt~disc_name~disc_degree~
        API->>API: Persist as presentation record
    end

    API-->>SU: { id, sdJwtPresentation, disclosedClaims }

    SU->>VE: Share sdJwtPresentation (QR code, deep-link, direct channel)

    VE->>API: POST /v1/presentations/verify { presentation }

    rect rgb(220, 255, 230)
        Note over API: 4-step verification pipeline
        API->>API: ① Verify issuer ES256 signature on JWT header.payload
        API->>API: ② For each disclosure: SHA-256(JSON([salt, key, val])) ∈ _sd array?
        API->>API: ③ Check issuerDid in trust_attestations (active, non-expired)
        API->>API: ④ Check credential status (active / revoked / expired)
    end

    API-->>VE: { valid: true, disclosedClaims: { name, degree },\n  issuerTrusted: true, credentialStatus: "active" }

    Note over VE: ✅ Verifier learns ONLY name + degree.<br/>GPA and nationality remain hidden.
```

---

## Part 4 — OID4VCI (Machine-to-Machine Issuance)

For wallet-to-server issuance following the HAIP 1.0 authorization-code flow with **PAR + PKCE + DPoP**.

```mermaid
sequenceDiagram
    autonumber
    participant W as 📱 Wallet / Client
    participant AS as Authorization Server<br/>(DID + HAIP API)
    participant CE as Credential Endpoint<br/>(/oauth/credentials)

    rect rgb(220, 235, 255)
        Note over W: Step 0 — Discover issuer capabilities
        W->>AS: GET /.well-known/openid-credential-issuer
        AS-->>W: { credential_endpoint, par_endpoint, token_endpoint,\n  credential_configurations_supported, dpop_signing_alg_values_supported: ["ES256"] }
    end

    rect rgb(255, 243, 220)
        Note over W: Step 1 — Pushed Authorization Request (PAR)
        W->>W: code_verifier = randomBytes(43-128 chars)
        W->>W: code_challenge = BASE64URL(SHA-256(code_verifier))
        W->>AS: POST /oauth/par<br/>{ response_type:code, client_id:walletDid,\n  redirect_uri, code_challenge, code_challenge_method:S256,\n  authorization_details:[{type, credential_configuration_id}] }
        AS-->>W: { request_uri: "urn:ietf:params:oauth:request_uri:...", expires_in: 90 }
    end

    rect rgb(220, 255, 230)
        Note over W: Step 2 — Authorization redirect
        W->>AS: GET /oauth/authorize?request_uri=urn:...&client_id=walletDid
        AS->>AS: Consume PAR → issue authorization code
        AS-->>W: 302 → redirect_uri?code=AUTH_CODE&state=...
    end

    rect rgb(245, 220, 255)
        Note over W: Step 3 — Token exchange with DPoP
        W->>W: Build DPoP proof JWT:<br/>{ typ:"dpop+jwt", alg:"ES256",<br/>  jwk: walletPublicKey,<br/>  htm:"POST", htu:"…/oauth/token", iat }
        W->>W: Sign DPoP proof with wallet P-256 key
        W->>AS: POST /oauth/token<br/>{ grant_type:authorization_code, code, redirect_uri,\n  client_id, code_verifier }<br/>DPoP: <proof JWT>
        AS->>AS: Verify DPoP proof (signature + htm/htu/iat)
        AS->>AS: Verify PKCE: BASE64URL(SHA-256(code_verifier)) == code_challenge
        AS-->>W: { access_token, token_type:"DPoP", expires_in:300,\n  c_nonce, c_nonce_expires_in }
    end

    rect rgb(255, 230, 220)
        Note over W: Step 4 — Request credential with key proof
        W->>W: Build key proof JWT:<br/>{ typ:"openid4vci-proof+jwt", alg:"ES256",<br/>  kid:walletDid, iss:walletDid,<br/>  aud:"http://localhost:3000",<br/>  iat, nonce: c_nonce }
        W->>W: Sign key proof with wallet P-256 key
        W->>W: Build fresh DPoP proof for /oauth/credentials
        W->>CE: POST /oauth/credentials<br/>{ format:"vc+sd-jwt", proof:{ proof_type:"jwt", jwt: keyProof } }<br/>Authorization: DPoP <access_token><br/>DPoP: <proof JWT>
        CE->>CE: Verify DPoP proof
        CE->>CE: Verify key proof nonce == c_nonce
        CE->>CE: Issue SD-JWT VC (or mso_mdoc)
        CE-->>W: { format:"vc+sd-jwt", credential:"eyJ..." }
    end
```

---

## Part 5 — OID4VP (Verifier-Initiated Presentation)

HAIP-compliant wallet presentation using **signed JAR request objects**, **direct_post**, and **KB-JWT holder binding**.

```mermaid
sequenceDiagram
    autonumber
    actor VE as 🔍 Verifier App
    participant API as DID + HAIP API
    participant W as 📱 Wallet / Subject

    rect rgb(220, 235, 255)
        Note over VE: Step 1 — Verifier initiates a VP session
        VE->>API: POST /oauth/vp/initiate<br/>{ dcqlQuery: { credentials: [{ format:"dc+sd-jwt",\n  meta:{vct_values:[...]}, claims:[{path:["name"]}] }] } }<br/>Authorization: Bearer <verifierToken>
        API->>API: Create VP session, generate nonce
        API-->>VE: { sessionId, requestUri:"http://…/oauth/request/{id}", nonce }
    end

    rect rgb(255, 243, 220)
        Note over W: Step 2 — Wallet fetches signed request object
        Note over VE,W: Verifier shares requestUri with wallet (QR code, deep-link)
        W->>API: GET /oauth/request/{sessionId}
        API->>API: Build JAR JWT:<br/>{ typ:"oauth-authz-req+jwt", alg:"ES256",\n  client_id:verifierDid, response_uri:"…/direct_post",\n  response_mode:"direct_post", nonce, dcql_query }
        API->>API: Sign JAR with verifier P-256 key
        API-->>W: Signed JAR JWT (application/oauth-authz-req+jwt)
        W->>W: Verify JAR signature against verifier DID document
    end

    rect rgb(220, 255, 230)
        Note over W: Step 3 — Wallet builds SD-JWT VP with KB-JWT

        W->>W: Select matching credential (SD-JWT VC)
        W->>W: Filter disclosures matching DCQL claims query
        W->>W: partialSdJwt = issuerJwt~disc_name~ (trailing ~)
        W->>W: sd_hash = BASE64URL(SHA-256(partialSdJwt))
        W->>W: Build KB-JWT:<br/>{ typ:"kb+jwt", alg:"ES256",\n  nonce (from JAR), aud:verifierDid,\n  iat, sd_hash }
        W->>W: Sign KB-JWT with holder P-256 key (matches cnf.jwk)
        W->>W: vpToken = issuerJwt~disc_name~kbJwt
    end

    rect rgb(245, 220, 255)
        Note over W: Step 4 — Submit VP via direct_post
        W->>API: POST /oauth/direct_post<br/>{ vp_token: vpToken, presentation_submission: {...} }

        rect rgb(255, 240, 220)
            Note over API: Verification pipeline
            API->>API: ① Decode issuer JWT + disclosures
            API->>API: ② Verify issuer ES256 signature
            API->>API: ③ Verify disclosure hashes ∈ _sd array
            API->>API: ④ Verify KB-JWT signature with cnf.jwk
            API->>API: ⑤ KB-JWT nonce == session nonce (replay prevention)
            API->>API: ⑥ KB-JWT sd_hash == SHA-256(partialSdJwt)
            API->>API: ⑦ Check trust registry (issuerDid)
            API->>API: ⑧ Check Token Status List (not revoked)
        end

        API->>API: Update VP session state → verified / failed
        API-->>W: { redirect_uri: "https://verifier.example.com/result?session=..." }
    end

    rect rgb(220, 255, 255)
        Note over VE: Step 5 — Verifier polls for result
        VE->>API: GET /oauth/vp-result/{sessionId}
        API-->>VE: { state:"verified",\n  disclosedClaims:{ name:"Alice Smith" },\n  verifiedAt }
    end
```

---

## Part 6 — KB-JWT Anatomy (Holder Binding)

The Key Binding JWT is what proves the person presenting the credential actually holds the private key corresponding to `cnf.jwk` in the issued credential.

```mermaid
flowchart TB
    subgraph Issued["Issued SD-JWT VC (stored by wallet)"]
        direction LR
        IJwt["issuerJwt\n(ES256 · P-256)\n─────────────\ncnf.jwk = holderPubKey\n_sd = [hash1, hash2, hash3]"]
        D1["~[salt1, name, Alice]~"]
        D2["~[salt2, degree, BSc]~"]
        D3["~[salt3, gpa, 3.9]~"]
    end

    subgraph Presentation["VP Token (sent to verifier)"]
        direction LR
        PJwt["issuerJwt"]
        PD1["~[salt1, name, Alice]~"]
        KB["kbJwt\n(ES256 · holderKey)\n─────────────\nnonce: session nonce\naud: verifierDid\nsd_hash: SHA-256(issuerJwt~disc1~)\niat: now"]
    end

    subgraph Checks["Verifier Checks"]
        C1["✅ issuerJwt signature\n(issuer P-256 key)"]
        C2["✅ disc_name hash ∈ _sd"]
        C3["✅ kbJwt signature\n(holderKey = cnf.jwk)"]
        C4["✅ nonce matches session"]
        C5["✅ sd_hash matches content"]
    end

    IJwt -->|"reveal name only\n(drop disc2, disc3)"| PJwt
    D1 --> PD1
    PJwt & PD1 -->|"sd_hash = SHA-256(ijwt~disc1~)"| KB
    PJwt --> C1
    PD1 --> C2
    KB --> C3 & C4 & C5

    style Issued fill:#dcffe8,stroke:#27ae60
    style Presentation fill:#f5dcff,stroke:#8e44ad
    style Checks fill:#fff3dc,stroke:#e6a817
```

---

## Part 7 — Revocation via Token Status List

```mermaid
sequenceDiagram
    autonumber
    actor IS as 🏛️ Issuer
    actor VE as 🔍 Verifier
    participant API as DID + HAIP API
    participant DB as PostgreSQL

    Note over IS: Issuer decides to revoke a credential
    IS->>API: POST /v1/credentials/{id}/revoke<br/>Authorization: Bearer <issuerToken>

    API->>DB: UPDATE credentials SET status='revoked' WHERE id=?
    API->>DB: Note: statusListId + statusListIndex already assigned at issuance

    Note over API: Next status list fetch will show bit=1 at this index

    VE->>API: GET /v1/credentials/status-lists/{statusListId}

    rect rgb(220, 255, 230)
        Note over API: Build Token Status List JWT
        API->>DB: SELECT all credentials WHERE status_list_id = ?
        API->>API: Build bitset: bit[statusListIndex] = 1 if revoked else 0
        API->>API: DEFLATE-compress bitset
        API->>API: Build JWT { typ:"statuslist+jwt",\n  status_list: { bits:1, lst: BASE64URL(compressed) } }
        API->>API: Sign JWT with issuer P-256 key (ES256)
    end

    API-->>VE: Signed Status List JWT (application/statuslist+jwt)

    VE->>VE: Verify JWT signature
    VE->>VE: Decompress bitset
    VE->>VE: Check bit at credential's statusListIndex
    VE->>VE: bit == 1 → REVOKED ❌
```

---

## Full End-to-End Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor AD as 🛡️ Admin
    actor AT as 🔐 Attester
    actor IS as 🏛️ Issuer
    actor SU as 👤 Subject
    actor VE as 🔍 Verifier
    participant API as DID + HAIP API

    rect rgb(220, 235, 255)
        Note over AD,API: Phase 1 — Account & Role Setup
        IS->>API: POST /v1/auth/signup { email, password, name }
        API-->>IS: { token, user: { did:"did:key:zDnae...", role:"subject" } }
        AT->>API: POST /v1/auth/signup { email, password, name }
        API-->>AT: { token, user: { did, role:"subject" } }
        SU->>API: POST /v1/auth/signup { email, password, name }
        API-->>SU: { token, user: { did, role:"subject" } }
        VE->>API: POST /v1/auth/signup { email, password, name }
        API-->>VE: { token, user: { did, role:"subject" } }

        AD->>API: POST /v1/admin/users/{isId}/role { role:"issuer" }
        AD->>API: POST /v1/admin/users/{atId}/role { role:"attester" }
        AD->>API: POST /v1/admin/users/{veId}/role { role:"verifier" }

        IS->>API: POST /v1/auth/login → fresh JWT (role:"issuer")
        AT->>API: POST /v1/auth/login → fresh JWT (role:"attester")
    end

    rect rgb(220, 255, 230)
        Note over AT,API: Phase 2 — Trust Setup
        AT->>API: POST /v1/trust/attest { issuerDid }
        API-->>AT: { id, issuerDid, attesterDid } — issuer now in trust registry
    end

    rect rgb(255, 243, 220)
        Note over IS,SU: Phase 3 — Credential Issuance
        IS->>API: POST /v1/credentials/issue<br/>{ subjectDid, credentialType:["UniversityDegree"],\n  claims:{ name, degree, gpa } }
        Note over API: ① Trust check ② SD-JWT VC (ES256) ③ mso_mdoc (COSE_Sign1)<br/>④ Ephemeral holder key ⑤ Token Status List index assigned
        API-->>IS: { id:credId, sdJwt, mdoc, holderKey }
        IS->>SU: Share credId out-of-band (QR code, secure message)
        SU->>API: GET /v1/credentials/{credId}
        API-->>SU: SD-JWT VC + mso_mdoc record
    end

    rect rgb(245, 220, 255)
        Note over SU,VE: Phase 4 — Selective Disclosure (REST path)
        SU->>API: POST /v1/presentations/derive<br/>{ credentialId:credId, revealedClaims:["name","degree"] }
        Note over API: Filter disclosures — GPA stays hidden
        API-->>SU: { sdJwtPresentation: "eyJ...~disc_name~disc_degree~" }

        SU->>VE: Send sdJwtPresentation
        VE->>API: POST /v1/presentations/verify { presentation }
        Note over API: ① ES256 sig ② disclosure hashes ③ trust check ④ status list
        API-->>VE: { valid:true, disclosedClaims:{ name, degree },\n  issuerTrusted:true, credentialStatus:"active" }
    end
```

---

## Credential & Presentation State Machine

```mermaid
stateDiagram-v2
    direction LR

    [*] --> Account_Created : POST /v1/auth/signup

    state "Account\n(role: subject)" as Account_Created
    state "Role Upgraded\n(issuer / attester / verifier)" as Role_Upgraded
    state "Issuer Trusted\n(active attestation)" as Issuer_Trusted
    state "Credential Issued\n(SD-JWT VC + mso_mdoc)" as VC_Active
    state "Presentation Derived\n(selective SD-JWT)" as VP_Derived
    state "Presentation Verified ✅" as VP_OK
    state "Presentation Failed ❌" as VP_FAIL
    state "Revoked" as VC_Revoked
    state "Expired" as VC_Expired

    Account_Created --> Role_Upgraded : POST /v1/admin/users/{id}/role
    Role_Upgraded --> Issuer_Trusted : POST /v1/trust/attest\n(attester vouches for issuer)
    Issuer_Trusted --> VC_Active : POST /v1/credentials/issue\n(ES256 SD-JWT + COSE_Sign1 mdoc)

    VC_Active --> VP_Derived : POST /v1/presentations/derive\n(subject · choose revealedClaims)
    VC_Active --> VC_Revoked : POST /v1/credentials/{id}/revoke\n(issuer · bit flipped in Status List)
    VC_Active --> VC_Expired : expiresAt reached

    VP_Derived --> VP_OK : POST /v1/presentations/verify\n✅ sig · hashes · trust · status
    VP_Derived --> VP_FAIL : POST /v1/presentations/verify\n❌ invalid sig OR revoked OR untrusted

    VC_Revoked --> [*]
    VC_Expired --> [*]
```

---

## Architecture

```
did-zkp/
├── src/
│   ├── domains/
│   │   ├── auth/           # DID challenge/response + JWT sessions
│   │   ├── users/          # Email/password accounts, profile, password reset, admin
│   │   ├── organizations/  # Org management, member roles, invites
│   │   ├── did/            # did:key creation and resolution (P-256)
│   │   ├── credentials/    # SD-JWT VC + mso_mdoc issuance, revocation, Token Status List
│   │   ├── presentation/   # SD-JWT selective disclosure + VP verification
│   │   ├── trust/          # Attester trust registry
│   │   └── oauth/          # OID4VCI (PAR · authorize · token · credentials)
│   │                       # OID4VP (vp/initiate · request · direct_post · vp-result)
│   ├── shared/
│   │   ├── crypto/
│   │   │   ├── p256.ts     # P-256 key generation, did:key multicodec encoding
│   │   │   ├── sd-jwt.ts   # SD-JWT VC issuance, selective disclosure, KB-JWT verification
│   │   │   ├── mdoc.ts     # ISO 18013-5 IssuerSigned builder + COSE_Sign1
│   │   │   ├── did-key.ts  # did:key document builder (Multikey / P-256)
│   │   │   └── keys.ts     # AES-GCM key encryption
│   │   └── middleware/     # Rate limiting, security headers, CORS
│   └── index.ts
├── tests/
│   ├── unit/crypto/        # sd-jwt, mdoc, p256 unit tests
│   ├── integration/        # Full lifecycle + revocation + trust
│   └── security/           # OWASP API Top 10 tests
├── migrations/
│   ├── 001–005_*.sql       # Base schema
│   ├── 006_haip_p1.sql     # P-256, SD-JWT columns, status list sequence
│   ├── 007_haip_p2.sql     # OID4VCI tables (PAR, auth codes, DPoP nonces)
│   └── 008_haip_p3.sql     # OID4VP table (VP sessions)
└── docs/superpowers/
    ├── specs/              # HAIP migration design spec
    └── plans/              # 13-task TDD implementation plan
```

---

## Tech Stack

| Concern | Library / API |
|---|---|
| HTTP Framework | [Hono](https://hono.dev) (Bun-native) |
| Cryptography | **Web Crypto API** (built into Bun) — P-256 keygen, ECDSA sign/verify, SHA-256 |
| CBOR encode/decode | `cbor2` — for mso_mdoc / COSE_Sign1 |
| JWT / JWK | `jose` — import/export JWK, JWT sign/verify |
| Database | PostgreSQL via `postgres` npm |
| Input Validation | `zod` |
| Session Tokens | `jose` (JWT HS256, 15-min TTL) |
| Key Encryption | AES-GCM (Web Crypto API) |
| Password Hashing | Bun built-in Argon2id (OWASP params) |

> **No external crypto libraries** — BLS12-381, `@digitalbazaar/*`, `jsonld`, and `@mattrglobal/bbs-signatures` have all been removed. All operations use the P-256 primitives available natively in the Bun/Web Crypto API.

---

## API Endpoints

All v1 endpoints are prefixed `/v1`. Protected routes require `Authorization: Bearer <token>`.

### Email Auth
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/auth/signup` | Public | Create account; P-256 `did:key` auto-generated |
| `POST` | `/v1/auth/login` | Public | Exchange email + password for JWT |
| `POST` | `/v1/auth/forgot-password` | Public | Request password reset token |
| `POST` | `/v1/auth/reset-password` | Public | Consume reset token, set new password |

### DID Authentication (challenge-response)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/auth/challenge` | Public | Request one-time nonce for a DID |
| `POST` | `/v1/auth/verify` | Public | Submit P-256 ECDSA signature, receive JWT |

### DID Management
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/dids` | Public | Generate P-256 `did:key` (private JWK returned **once**) |
| `GET` | `/v1/dids/me` | Any role | Get your own DID document |
| `GET` | `/v1/dids/:did` | Public | Resolve any DID document |
| `DELETE` | `/v1/dids/:did` | Owner | Deactivate a DID |

### Users
| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/users/me` | Any role | Get profile (includes org memberships) |
| `PATCH` | `/v1/users/me` | Any role | Update name or organizationName |

### Admin
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/admin/users/:id/role` | `X-Admin-Secret` | Upgrade user's DID role |

### Organizations
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/organizations` | Any role | Create org with its own P-256 DID |
| `GET` | `/v1/organizations/:id` | Member | Get org details |
| `DELETE` | `/v1/organizations/:id` | Owner | Delete org and deactivate its DID |
| `GET` | `/v1/organizations/:id/members` | Member | List members |
| `POST` | `/v1/organizations/:id/invites` | Admin/Owner | Invite user by email |
| `POST` | `/v1/organizations/invites/:token/accept` | Any role | Accept pending invite |
| `PATCH` | `/v1/organizations/:id/members/:userId` | Admin/Owner | Change member's org role |
| `DELETE` | `/v1/organizations/:id/members/:userId` | Admin/Owner or self | Remove member |

### Verifiable Credentials
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/credentials/issue` | Issuer | Issue SD-JWT VC + mso_mdoc to subject |
| `GET` | `/v1/credentials` | Issuer | List all issued credentials |
| `GET` | `/v1/credentials/:id` | Issuer / Subject | Fetch credential by ID |
| `POST` | `/v1/credentials/:id/revoke` | Issuer | Revoke credential (updates Token Status List) |
| `GET` | `/v1/credentials/:id/status` | Public | Check credential status |
| `GET` | `/v1/credentials/status-lists/:id` | Public | Token Status List 1.0 JWT |

### Verifiable Presentations
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/presentations/derive` | Subject | Derive SD-JWT selective-disclosure VP |
| `POST` | `/v1/presentations/verify` | Verifier | Verify VP (sig + hashes + trust + revocation) |
| `GET` | `/v1/presentations/:id` | Subject | Fetch previously derived presentation |

### Trust Registry
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/trust/attest` | Attester | Vouch for an issuer DID |
| `GET` | `/v1/trust/issuers` | Public | List all trusted issuers |
| `GET` | `/v1/trust/issuers/:did` | Public | Check if DID is a trusted issuer |
| `POST` | `/v1/trust/attest/:id/revoke` | Attester | Revoke an issuer attestation |

### OID4VCI (HAIP authorization-code flow)
| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/.well-known/openid-credential-issuer` | Public | OID4VCI issuer metadata |
| `POST` | `/oauth/par` | Public | Pushed Authorization Request (PAR + PKCE) |
| `GET` | `/oauth/authorize` | Public | Authorization code redirect |
| `POST` | `/oauth/token` | DPoP | Token endpoint (DPoP-bound access token + c_nonce) |
| `POST` | `/oauth/nonce` | DPoP | Refresh c_nonce |
| `POST` | `/oauth/credentials` | DPoP | Credential endpoint (key proof JWT required) |

### OID4VP (HAIP verifier-initiated flow)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/oauth/vp/initiate` | Verifier | Start VP session (DCQL query) |
| `GET` | `/oauth/request/:id` | Public | Fetch signed JAR request object |
| `POST` | `/oauth/direct_post` | Public | Submit VP token (SD-JWT + KB-JWT) |
| `GET` | `/oauth/vp-result/:id` | Verifier | Poll VP verification result |

---

## Security

### OWASP API Security Top 10

| # | Threat | Control |
|---|---|---|
| API1 | Broken Object Level Authorization | Ownership enforced per resource; org invite BOLA: caller email must match invite email |
| API2 | Broken Authentication | Single-use nonces (5-min TTL); P-256 ECDSA sig verification; short-lived JWTs (15-min); Argon2id passwords; timing-safe comparison; DPoP proof anti-replay |
| API3 | Broken Object Property Level Authorization | Response serializers strip fields by role |
| API4 | Unrestricted Resource Consumption | Rate limiting: 100 req/min general, 10 req/min on issuance; 64 KB body cap |
| API5 | Broken Function Level Authorization | Role checked at middleware before any handler; org role hierarchy (member < admin < owner) enforced per operation |
| API6 | Unsafe Business Flows | Issuance requires role + active trust attestation; last-owner removal blocked; KB-JWT nonce binding prevents VP replay |
| API7 | SSRF | Zero outbound HTTP during request handling (no JSON-LD, no external resolvers) |
| API8 | Security Misconfiguration | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Cache-Control: no-store on every response |
| API9 | Improper Inventory Management | All endpoints versioned under `/v1/` or `/oauth/` |
| API10 | Unsafe Input Consumption | Zod schemas on all inputs; DPoP htm/htu/iat validation |

### Privacy Controls

- **SD-JWT selective disclosure** — verifiers receive *only* the claims the subject chose to reveal; all other claims are cryptographically hidden
- **Holder binding via KB-JWT** — proves the presenter holds the private key matching `cnf.jwk`; prevents credential theft attacks
- **DPoP (RFC 9449)** — access tokens are key-bound; stolen tokens cannot be replayed from a different client
- **Private keys never stored** — raw private keys returned only once at creation; server stores AES-GCM encrypted form, decrypts only during signing
- **Append-only audit log** — every issuance, revocation, verification, and auth event recorded; claim values never logged
- **Password reset** — all active sessions invalidated on successful reset

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
# Generate secrets:
openssl rand -hex 32    # → KEY_ENCRYPTION_SECRET
openssl rand -base64 32 # → JWT_SECRET
openssl rand -hex 32    # → ADMIN_SECRET

# Create the database
createdb did_zkp

# Start the server (runs all migrations automatically)
bun run dev
```

### Verify

```bash
curl http://localhost:3000/health
# → {"status":"ok"}

# Discover OID4VCI capabilities
curl http://localhost:3000/.well-known/openid-credential-issuer
```

### Interactive API Docs

Open [http://localhost:3000/docs](http://localhost:3000/docs) for the Scalar UI — all 44 endpoints with schemas, examples, and try-it-out.

### Running Tests

```bash
createdb did_zkp_test

bun test:unit         # Crypto unit tests (SD-JWT, mso_mdoc, P-256)
bun test:integration  # Full lifecycle + revocation + trust flows
bun test:security     # OWASP API Top 10 security tests
bun test              # All tests
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `TEST_DATABASE_URL` | Tests | PostgreSQL connection string for test DB |
| `KEY_ENCRYPTION_SECRET` | Yes | 64-char hex (32 bytes) for AES-GCM private key encryption |
| `JWT_SECRET` | Yes | Secret for signing session JWTs |
| `ADMIN_SECRET` | Yes | Secret for `X-Admin-Secret` header on admin endpoints |
| `CORS_ORIGIN` | No | Allowed CORS origin (default: `http://localhost:3000`) |
| `PORT` | No | HTTP port (default: `3000`) |
| `NODE_ENV` | No | `development` or `production` |

---

## Database Schema

### Account & Identity
- **`users`** — email/password accounts, name, FK → dids
- **`password_reset_tokens`** — one-time reset tokens with expiry
- **`dids`** — DID documents, P-256 public key JWK, AES-GCM encrypted private key, role
- **`sessions`** — JWT session records (15-min TTL)
- **`auth_challenges`** — single-use nonces for DID challenge-response (5-min TTL)

### Organizations
- **`organizations`** — org name, slug, DID, owner FK
- **`org_members`** — user ↔ org membership with role
- **`org_invites`** — pending invites with email, token, expiry

### Credentials & Trust
- **`credentials`** — SD-JWT VC, mso_mdoc, holder key, Token Status List position, status
- **`presentations`** — derived SD-JWT VPs (issuer JWT + selected disclosures)
- **`trust_attestations`** — attestation records linking attesters to authorized issuers
- **`audit_log`** — append-only event log (DB trigger blocks UPDATE/DELETE)

### OID4VCI
- **`oauth_par_requests`** — PAR entries with PKCE code_challenge, authorization_details (90s TTL)
- **`oauth_auth_codes`** — authorization codes post-redirect (5-min TTL)
- **`oauth_dpop_nonces`** — DPoP nonce anti-replay store

### OID4VP
- **`vp_sessions`** — VP session state (pending → verified / failed / expired), DCQL query, nonce, result

---

## Standards & References

- [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [SD-JWT VC — draft-ietf-oauth-sd-jwt-vc](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html)
- [SD-JWT — RFC draft-ietf-oauth-selective-disclosure-jwt](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- [Token Status List — draft-ietf-oauth-status-list](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html)
- [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [RFC 9449 — DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126)
- [ISO 18013-5 mso_mdoc](https://www.iso.org/standard/69084.html)
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
