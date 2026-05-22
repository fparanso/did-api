# DID+ZKP REST API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Bun + Hono REST API implementing did:key, BBS+ selective-disclosure Verifiable Credentials, and DID Auth with full OWASP API Security Top 10 compliance.

**Architecture:** Domain-Driven Modular — five domains (auth, did, credentials, presentation, trust) each own their routes, service, and repository. Shared crypto (Ed25519 + BLS12-381/BBS+), JSON-LD offline loader, and security middleware live in `src/shared/`. Per-route middleware enforces JWT auth and role checks explicitly.

**Tech Stack:** Bun, Hono, PostgreSQL (`postgres` npm), `@digitalbazaar/did-method-key`, `@digitalbazaar/ed25519-verification-key-2020`, `@digitalbazaar/bbs-cryptosuite-2023`, `@digitalbazaar/data-integrity`, `@digitalbazaar/vc`, `jsonld`, `jose`, `zod`

---

## File Map

```
src/
  shared/
    types.ts
    errors.ts
    db.ts
    crypto/
      keys.ts        # AES-GCM encrypt/decrypt private keys
      did-key.ts     # did:key generation (Ed25519) + BLS12-381 key gen
      bbs.ts         # BBS+ sign / derive / verify wrappers
    jsonld/
      loader.ts      # Offline document loader + context allowlist
      contexts/      # Downloaded JSON-LD context JSON files
    middleware/
      rate-limit.ts
      security-headers.ts
      cors.ts
  migrations/
    001_init.sql
    002_audit.sql
  domains/
    auth/
      repository.ts  # challenge CRUD, session CRUD
      service.ts     # nonce gen, DID Auth verify, JWT issue
      middleware.ts  # jwtMiddleware, requireRole()
      routes.ts      # POST /challenge, POST /verify
    did/
      repository.ts
      service.ts
      routes.ts
    credentials/
      repository.ts
      service.ts
      routes.ts
    presentation/
      repository.ts
      service.ts
      routes.ts
    trust/
      repository.ts
      service.ts
      routes.ts
  index.ts
tests/
  fixtures/
    generate.ts
    issuer-did.json
    subject-did.json
    attester-did.json
    verifier-did.json
    sample-vc.json
    sample-vp.json
  unit/
    errors.test.ts
    crypto/keys.test.ts
    crypto/did-key.test.ts
    crypto/bbs.test.ts
    jsonld/loader.test.ts
    middleware/security.test.ts
  integration/
    auth.test.ts
    did.test.ts
    credentials.test.ts
    presentation.test.ts
    trust.test.ts
    lifecycle.test.ts
  security/
    owasp.test.ts
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `bunfig.toml`
- Create: `.env.example`
- Create: `.gitignore`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "did-zkp",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "bun run --watch src/index.ts",
    "start": "bun run src/index.ts",
    "test": "bun test",
    "test:unit": "bun test tests/unit",
    "test:integration": "bun test tests/integration",
    "test:security": "bun test tests/security"
  },
  "dependencies": {
    "hono": "^4.4.0",
    "@digitalbazaar/did-method-key": "^5.3.0",
    "@digitalbazaar/ed25519-verification-key-2020": "^4.2.0",
    "@digitalbazaar/bbs-cryptosuite-2023": "^1.0.0",
    "@digitalbazaar/data-integrity": "^2.1.0",
    "@digitalbazaar/vc": "^7.0.0",
    "jsonld": "^8.3.2",
    "postgres": "^3.4.4",
    "jose": "^5.6.3",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@types/bun": "latest"
  }
}
```

- [ ] **Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "skipLibCheck": true,
    "outDir": "./dist",
    "resolveJsonModule": true
  },
  "include": ["src", "tests"]
}
```

- [ ] **Step 3: Create bunfig.toml**

```toml
[test]
timeout = 30000
```

- [ ] **Step 4: Create .env.example**

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/did_zkp
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/did_zkp_test
KEY_ENCRYPTION_SECRET=0000000000000000000000000000000000000000000000000000000000000000
JWT_SECRET=change-me-in-production
CORS_ORIGIN=http://localhost:3000
PORT=3000
NODE_ENV=development
```

- [ ] **Step 5: Create .gitignore**

```
node_modules/
dist/
.env
*.local
```

- [ ] **Step 6: Install dependencies**

```bash
bun install
```

Expected: `node_modules/` created, no errors.

- [ ] **Step 7: Commit**

```bash
git add package.json tsconfig.json bunfig.toml .env.example .gitignore
git commit -m "chore: project scaffold"
```

---

## Task 2: Shared Types

**Files:**
- Create: `src/shared/types.ts`

- [ ] **Step 1: Write types.ts**

```typescript
// src/shared/types.ts
export type Role = 'subject' | 'issuer' | 'verifier' | 'attester'
export type AuditAction = 'issue' | 'revoke' | 'verify' | 'attest' | 'auth'
export type ResourceStatus = 'active' | 'revoked'

export interface DidRecord {
  id: string
  role: Role
  document: Record<string, unknown>
  publicKey: string           // Ed25519 multibase (for DID Auth)
  privateKey: string          // AES-GCM encrypted Ed25519 private key
  blsPublicKey: string | null // BLS12-381 G2 multibase (issuers only)
  blsPrivateKey: string | null // AES-GCM encrypted BLS12-381 (issuers only)
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
}
```

- [ ] **Step 2: Commit**

```bash
git add src/shared/types.ts
git commit -m "feat: shared types"
```

---

## Task 3: Shared Errors + Tests

**Files:**
- Create: `src/shared/errors.ts`
- Create: `tests/unit/errors.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/errors.test.ts
import { describe, test, expect } from 'bun:test'
import { AppError, Errors } from '../../src/shared/errors'

describe('AppError', () => {
  test('constructs with code, message, status', () => {
    const e = new AppError('TEST', 'test message', 400)
    expect(e.code).toBe('TEST')
    expect(e.message).toBe('test message')
    expect(e.status).toBe(400)
    expect(e instanceof Error).toBe(true)
  })
})

describe('Errors factory', () => {
  test('DID_NOT_FOUND returns 404', () => {
    const e = Errors.DID_NOT_FOUND('did:key:z6Mk')
    expect(e.status).toBe(404)
    expect(e.code).toBe('DID_NOT_FOUND')
  })

  test('INVALID_PROOF returns 422', () => {
    expect(Errors.INVALID_PROOF().status).toBe(422)
  })

  test('UNAUTHORIZED_ROLE returns 403', () => {
    expect(Errors.UNAUTHORIZED_ROLE().status).toBe(403)
  })

  test('CHALLENGE_EXPIRED returns 401', () => {
    expect(Errors.CHALLENGE_EXPIRED().status).toBe(401)
  })
})
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
bun test tests/unit/errors.test.ts
```

Expected: `Cannot find module '../../src/shared/errors'`

- [ ] **Step 3: Implement errors.ts**

```typescript
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
```

- [ ] **Step 4: Run test — expect PASS**

```bash
bun test tests/unit/errors.test.ts
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/shared/errors.ts tests/unit/errors.test.ts
git commit -m "feat: shared error classes"
```

---

## Task 4: Database Setup + Migrations

**Files:**
- Create: `src/shared/db.ts`
- Create: `src/migrations/001_init.sql`
- Create: `src/migrations/002_audit.sql`

- [ ] **Step 1: Create 001_init.sql**

```sql
-- src/migrations/001_init.sql
CREATE TABLE IF NOT EXISTS dids (
  id              TEXT PRIMARY KEY,
  role            TEXT NOT NULL CHECK (role IN ('subject','issuer','verifier','attester')),
  document        JSONB NOT NULL,
  public_key      TEXT NOT NULL,
  private_key     TEXT NOT NULL,
  bls_public_key  TEXT,
  bls_private_key TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  deactivated_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS credentials (
  id          TEXT PRIMARY KEY,
  issuer_did  TEXT NOT NULL REFERENCES dids(id),
  subject_did TEXT NOT NULL REFERENCES dids(id),
  type        TEXT[] NOT NULL,
  claims      JSONB NOT NULL,
  document    JSONB NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS presentations (
  id               TEXT PRIMARY KEY,
  holder_did       TEXT NOT NULL REFERENCES dids(id),
  credential_ids   TEXT[] NOT NULL,
  document         JSONB NOT NULL,
  disclosed_claims JSONB NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trust_attestations (
  id           TEXT PRIMARY KEY,
  attester_did TEXT NOT NULL REFERENCES dids(id),
  issuer_did   TEXT NOT NULL REFERENCES dids(id),
  credential   JSONB NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_challenges (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did        TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used       BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS sessions (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  did        TEXT NOT NULL,
  role       TEXT NOT NULL,
  token      TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
```

- [ ] **Step 2: Create 002_audit.sql**

```sql
-- src/migrations/002_audit.sql
CREATE TABLE IF NOT EXISTS audit_log (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_did  TEXT NOT NULL,
  action     TEXT NOT NULL CHECK (action IN ('issue','revoke','verify','attest','auth')),
  target_id  TEXT,
  result     TEXT NOT NULL CHECK (result IN ('success','failure')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent UPDATE and DELETE on audit_log via a trigger
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER audit_log_immutable
  BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
```

- [ ] **Step 3: Implement db.ts**

```typescript
// src/shared/db.ts
import postgres from 'postgres'
import { readdir, readFile } from 'fs/promises'
import { join } from 'path'

export const sql = postgres(process.env.DATABASE_URL!, {
  max: 10,
  transform: postgres.camel,
})

export async function runMigrations(): Promise<void> {
  await sql`
    CREATE TABLE IF NOT EXISTS _migrations (
      name    TEXT PRIMARY KEY,
      run_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `
  const applied = new Set(
    (await sql`SELECT name FROM _migrations`).map((r: { name: string }) => r.name)
  )
  const dir = join(import.meta.dir, '../migrations')
  const files = (await readdir(dir)).filter(f => f.endsWith('.sql')).sort()
  for (const file of files) {
    if (applied.has(file)) continue
    const content = await readFile(join(dir, file), 'utf-8')
    await sql.begin(async tx => {
      await tx.unsafe(content)
      await tx`INSERT INTO _migrations (name) VALUES (${file})`
    })
    console.log(`[db] migrated: ${file}`)
  }
}

export async function writeAuditLog(
  actorDid: string,
  action: string,
  result: 'success' | 'failure',
  targetId?: string
): Promise<void> {
  await sql`
    INSERT INTO audit_log (actor_did, action, target_id, result)
    VALUES (${actorDid}, ${action}, ${targetId ?? null}, ${result})
  `
}
```

- [ ] **Step 4: Create test DB and verify migrations run**

```bash
createdb did_zkp_test 2>/dev/null || true
DATABASE_URL=postgresql://localhost/did_zkp_test bun -e "
  import { runMigrations } from './src/shared/db.ts'
  await runMigrations()
  console.log('OK')
  process.exit(0)
"
```

Expected: `[db] migrated: 001_init.sql`, `[db] migrated: 002_audit.sql`, `OK`

- [ ] **Step 5: Commit**

```bash
git add src/shared/db.ts src/migrations/
git commit -m "feat: database setup and migrations"
```

---

## Task 5: AES-GCM Key Encryption

**Files:**
- Create: `src/shared/crypto/keys.ts`
- Create: `tests/unit/crypto/keys.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/crypto/keys.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { encryptKey, decryptKey } from '../../../src/shared/crypto/keys'

describe('encryptKey / decryptKey', () => {
  beforeAll(() => {
    process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64) // 32 bytes hex
  })

  test('round-trip preserves the value', async () => {
    const original = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
    const encrypted = await encryptKey(original)
    const decrypted = await decryptKey(encrypted)
    expect(decrypted).toBe(original)
  })

  test('each encryption produces a unique ciphertext', async () => {
    const val = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
    const enc1 = await encryptKey(val)
    const enc2 = await encryptKey(val)
    expect(enc1).not.toBe(enc2)
  })

  test('ciphertext contains iv separator', async () => {
    const encrypted = await encryptKey('test')
    expect(encrypted).toContain(':')
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

```bash
bun test tests/unit/crypto/keys.test.ts
```

- [ ] **Step 3: Implement keys.ts**

```typescript
// src/shared/crypto/keys.ts
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

async function getKey(): Promise<CryptoKey> {
  const secret = process.env.KEY_ENCRYPTION_SECRET
  if (!secret || secret.length !== 64) {
    throw new Error('KEY_ENCRYPTION_SECRET must be a 64-char hex string (32 bytes)')
  }
  return crypto.subtle.importKey(
    'raw', hexToBytes(secret), 'AES-GCM', false, ['encrypt', 'decrypt']
  )
}

export async function encryptKey(value: string): Promise<string> {
  const key = await getKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new TextEncoder().encode(value)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
  const ivB64 = Buffer.from(iv).toString('base64')
  const encB64 = Buffer.from(encrypted).toString('base64')
  return `${ivB64}:${encB64}`
}

export async function decryptKey(stored: string): Promise<string> {
  const [ivB64, encB64] = stored.split(':')
  if (!ivB64 || !encB64) throw new Error('Invalid encrypted key format')
  const key = await getKey()
  const iv = Buffer.from(ivB64, 'base64')
  const encrypted = Buffer.from(encB64, 'base64')
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encrypted)
  return new TextDecoder().decode(decrypted)
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
bun test tests/unit/crypto/keys.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/shared/crypto/keys.ts tests/unit/crypto/keys.test.ts
git commit -m "feat: AES-GCM private key encryption"
```

---

## Task 6: DID Key Generation

**Files:**
- Create: `src/shared/crypto/did-key.ts`
- Create: `tests/unit/crypto/did-key.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/crypto/did-key.test.ts
import { describe, test, expect } from 'bun:test'
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../../src/shared/crypto/did-key'

describe('generateDidKey', () => {
  test('returns a did:key DID starting with did:key:z6Mk', async () => {
    const result = await generateDidKey()
    expect(result.did).toMatch(/^did:key:z6Mk/)
    expect(result.publicKeyMultibase).toMatch(/^z6Mk/)
    expect(result.privateKeyMultibase).toBeTruthy()
  })

  test('each call produces a unique DID', async () => {
    const a = await generateDidKey()
    const b = await generateDidKey()
    expect(a.did).not.toBe(b.did)
  })
})

describe('generateBlsKeyPair', () => {
  test('returns multibase-encoded BLS12-381 G2 key pair', async () => {
    const result = await generateBlsKeyPair('did:key:z6MkTest')
    expect(result.publicKeyMultibase).toMatch(/^zUC/)
    expect(result.secretKeyMultibase).toBeTruthy()
  })
})

describe('buildDidDocument', () => {
  test('produces a valid DID document shape', async () => {
    const { did, publicKeyMultibase } = await generateDidKey()
    const doc = buildDidDocument(did, publicKeyMultibase)
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1')
    expect(doc.id).toBe(did)
    expect(doc.verificationMethod).toHaveLength(1)
    expect(doc.authentication).toHaveLength(1)
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

```bash
bun test tests/unit/crypto/did-key.test.ts
```

- [ ] **Step 3: Implement did-key.ts**

```typescript
// src/shared/crypto/did-key.ts
import { driver } from '@digitalbazaar/did-method-key'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { Bbs2023Multikey } from '@digitalbazaar/bbs-cryptosuite-2023'

const didKeyDriver = driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from,
})

export interface DidKeyResult {
  did: string
  publicKeyMultibase: string
  privateKeyMultibase: string
}

export async function generateDidKey(): Promise<DidKeyResult> {
  const keyPair = await Ed25519VerificationKey2020.generate()
  const did = `did:key:${keyPair.publicKeyMultibase}`
  keyPair.controller = did
  keyPair.id = `${did}#${keyPair.publicKeyMultibase}`
  return {
    did,
    publicKeyMultibase: keyPair.publicKeyMultibase!,
    privateKeyMultibase: keyPair.privateKeyMultibase!,
  }
}

export interface BlsKeyResult {
  publicKeyMultibase: string
  secretKeyMultibase: string
}

export async function generateBlsKeyPair(controller: string): Promise<BlsKeyResult> {
  const keyPair = await Bbs2023Multikey.generate({
    algorithm: 'BBS-BLS12-381-SHA-256',
    controller,
  })
  return {
    publicKeyMultibase: keyPair.publicKeyMultibase,
    secretKeyMultibase: keyPair.secretKeyMultibase,
  }
}

export function buildDidDocument(
  did: string,
  publicKeyMultibase: string,
  blsPublicKeyMultibase?: string
): Record<string, unknown> {
  const keyId = `${did}#${publicKeyMultibase}`
  const contexts: string[] = [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
  ]
  const verificationMethods: object[] = [{
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase,
  }]

  if (blsPublicKeyMultibase) {
    contexts.push('https://w3id.org/security/multikey/v1')
    verificationMethods.push({
      id: `${did}#${blsPublicKeyMultibase}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: blsPublicKeyMultibase,
    })
  }

  return {
    '@context': contexts,
    id: did,
    verificationMethod: verificationMethods,
    authentication: [keyId],
    assertionMethod: blsPublicKeyMultibase
      ? [keyId, `${did}#${blsPublicKeyMultibase}`]
      : [keyId],
    capabilityInvocation: [keyId],
    capabilityDelegation: [keyId],
  }
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
bun test tests/unit/crypto/did-key.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/shared/crypto/did-key.ts tests/unit/crypto/did-key.test.ts
git commit -m "feat: did:key + BLS12-381 key generation"
```

---

## Task 7: JSON-LD Offline Context Loader

**Files:**
- Create: `src/shared/jsonld/loader.ts`
- Create: `src/shared/jsonld/contexts/` (downloaded files)
- Create: `tests/unit/jsonld/loader.test.ts`

- [ ] **Step 1: Download JSON-LD contexts and save as files**

```bash
mkdir -p src/shared/jsonld/contexts

# W3C VC 2.0
curl -sL "https://www.w3.org/ns/credentials/v2" -H "Accept: application/ld+json" \
  -o src/shared/jsonld/contexts/credentials-v2.json

# Data Integrity v2
curl -sL "https://w3id.org/security/data-integrity/v2" -H "Accept: application/ld+json" \
  -o src/shared/jsonld/contexts/data-integrity-v2.json

# Multikey v1
curl -sL "https://w3id.org/security/multikey/v1" -H "Accept: application/ld+json" \
  -o src/shared/jsonld/contexts/multikey-v1.json

# Ed25519 2020
curl -sL "https://w3id.org/security/suites/ed25519-2020/v1" -H "Accept: application/ld+json" \
  -o src/shared/jsonld/contexts/ed25519-2020-v1.json

# DID v1
curl -sL "https://www.w3.org/ns/did/v1" -H "Accept: application/ld+json" \
  -o src/shared/jsonld/contexts/did-v1.json
```

Verify each file is non-empty valid JSON: `cat src/shared/jsonld/contexts/credentials-v2.json | bun -e "import {createReadStream} from 'fs'; JSON.parse(await Bun.file('src/shared/jsonld/contexts/credentials-v2.json').text()); console.log('OK')"`

- [ ] **Step 2: Write failing test**

```typescript
// tests/unit/jsonld/loader.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { initContextLoader, getDocumentLoader } from '../../../src/shared/jsonld/loader'

describe('context loader', () => {
  beforeAll(async () => {
    await initContextLoader()
  })

  test('loads a known context by URL', async () => {
    const loader = getDocumentLoader()
    const result = await loader('https://www.w3.org/ns/credentials/v2')
    expect(result.document).toBeTruthy()
    expect((result.document as any)['@context']).toBeTruthy()
  })

  test('throws INVALID_CONTEXT for unknown URL', async () => {
    const loader = getDocumentLoader()
    await expect(loader('https://evil.example/bad-context')).rejects.toThrow('INVALID_CONTEXT')
  })
})
```

- [ ] **Step 3: Run — expect FAIL**

```bash
bun test tests/unit/jsonld/loader.test.ts
```

- [ ] **Step 4: Implement loader.ts**

```typescript
// src/shared/jsonld/loader.ts
import { join } from 'path'
import { AppError } from '../errors.js'

const ALLOWED_CONTEXTS = new Map<string, string>([
  ['https://www.w3.org/ns/credentials/v2',               'credentials-v2.json'],
  ['https://w3id.org/security/data-integrity/v2',        'data-integrity-v2.json'],
  ['https://w3id.org/security/multikey/v1',              'multikey-v1.json'],
  ['https://w3id.org/security/suites/ed25519-2020/v1',   'ed25519-2020-v1.json'],
  ['https://www.w3.org/ns/did/v1',                       'did-v1.json'],
])

const contextCache = new Map<string, object>()
let didResolver: ((did: string) => Promise<object>) | null = null

export async function initContextLoader(): Promise<void> {
  const dir = join(import.meta.dir, 'contexts')
  for (const [url, file] of ALLOWED_CONTEXTS) {
    const doc = await Bun.file(join(dir, file)).json()
    contextCache.set(url, doc)
  }
}

export function setDidResolver(resolver: (did: string) => Promise<object>): void {
  didResolver = resolver
}

export function getDocumentLoader() {
  return async (url: string): Promise<{ contextUrl: null; document: object; documentUrl: string }> => {
    if (url.startsWith('did:key:') || url.startsWith('did:key:z')) {
      const did = url.split('#')[0]
      if (!didResolver) throw new Error('DID resolver not initialized')
      const document = await didResolver(did)
      return { contextUrl: null, document, documentUrl: url }
    }
    const doc = contextCache.get(url)
    if (!doc) throw new AppError('INVALID_CONTEXT', `Unknown context: ${url}`, 422)
    return { contextUrl: null, document: doc, documentUrl: url }
  }
}
```

- [ ] **Step 5: Run — expect PASS**

```bash
bun test tests/unit/jsonld/loader.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add src/shared/jsonld/ tests/unit/jsonld/
git commit -m "feat: offline JSON-LD context loader"
```

---

## Task 8: BBS+ Crypto Wrappers

**Files:**
- Create: `src/shared/crypto/bbs.ts`
- Create: `tests/unit/crypto/bbs.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/crypto/bbs.test.ts
import { describe, test, expect, beforeAll } from 'bun:test'
import { signCredential, deriveProof, verifyPresentation } from '../../../src/shared/crypto/bbs'
import { generateBlsKeyPair } from '../../../src/shared/crypto/did-key'
import { Bbs2023Multikey } from '@digitalbazaar/bbs-cryptosuite-2023'
import { initContextLoader } from '../../../src/shared/jsonld/loader'

const ISSUER_DID = 'did:key:zUC7TestIssuer'

describe('BBS+ sign / derive / verify', () => {
  let keyPair: InstanceType<typeof Bbs2023Multikey>
  let signedVc: object

  beforeAll(async () => {
    await initContextLoader()
    const { publicKeyMultibase, secretKeyMultibase } = await generateBlsKeyPair(ISSUER_DID)
    keyPair = await Bbs2023Multikey.from({
      id: `${ISSUER_DID}#${publicKeyMultibase}`,
      controller: ISSUER_DID,
      publicKeyMultibase,
      secretKeyMultibase,
    })
  })

  test('signCredential returns a VC with a DataIntegrityProof', async () => {
    const credential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      credentialSubject: { id: 'did:key:zSubject', name: 'Alice', degree: 'BSc' },
    }
    signedVc = await signCredential(credential, keyPair)
    expect((signedVc as any).proof).toBeTruthy()
    expect((signedVc as any).proof.type).toBe('DataIntegrityProof')
  })

  test('deriveProof discloses only selected claims', async () => {
    const derived = await deriveProof(signedVc, ['/credentialSubject/name'])
    expect((derived as any).credentialSubject.name).toBe('Alice')
    expect((derived as any).credentialSubject.degree).toBeUndefined()
  })

  test('verifyPresentation returns true for a valid derived proof', async () => {
    const derived = await deriveProof(signedVc, ['/credentialSubject/name'])
    const valid = await verifyPresentation(derived)
    expect(valid).toBe(true)
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

```bash
bun test tests/unit/crypto/bbs.test.ts
```

- [ ] **Step 3: Implement bbs.ts**

```typescript
// src/shared/crypto/bbs.ts
import {
  createSignCryptosuite,
  createDiscloseCryptosuite,
  createVerifyCryptosuite,
  Bbs2023Multikey,
} from '@digitalbazaar/bbs-cryptosuite-2023'
import { DataIntegrityProof } from '@digitalbazaar/data-integrity'
import * as vc from '@digitalbazaar/vc'
import { getDocumentLoader } from '../jsonld/loader.js'

export async function signCredential(
  credential: object,
  keyPair: InstanceType<typeof Bbs2023Multikey>
): Promise<object> {
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(),
    cryptosuite: createSignCryptosuite(),
  })
  return vc.issue({ credential, suite, documentLoader: getDocumentLoader() })
}

export async function deriveProof(
  signedVc: object,
  selectivePointers: string[]
): Promise<object> {
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({ selectivePointers }),
  })
  return vc.derive({ verifiableCredential: signedVc, suite, documentLoader: getDocumentLoader() })
}

export async function verifyPresentation(derivedVcOrVp: object): Promise<boolean> {
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite(),
  })
  const result = await vc.verify({
    presentation: derivedVcOrVp,
    suite,
    documentLoader: getDocumentLoader(),
  })
  return result.verified
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
bun test tests/unit/crypto/bbs.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/shared/crypto/bbs.ts tests/unit/crypto/bbs.test.ts
git commit -m "feat: BBS+ sign/derive/verify wrappers"
```

---

## Task 9: Security Middleware

**Files:**
- Create: `src/shared/middleware/rate-limit.ts`
- Create: `src/shared/middleware/security-headers.ts`
- Create: `src/shared/middleware/cors.ts`
- Create: `tests/unit/middleware/security.test.ts`

- [ ] **Step 1: Write failing test**

```typescript
// tests/unit/middleware/security.test.ts
import { describe, test, expect } from 'bun:test'
import { Hono } from 'hono'
import { createRateLimiter } from '../../../src/shared/middleware/rate-limit'
import { securityHeadersMiddleware } from '../../../src/shared/middleware/security-headers'

describe('rate limiter', () => {
  test('allows requests under the limit', async () => {
    const app = new Hono()
    app.use('*', createRateLimiter(5, 60_000))
    app.get('/', c => c.json({ ok: true }))
    const res = await app.request('/')
    expect(res.status).toBe(200)
  })

  test('blocks requests over the limit', async () => {
    const app = new Hono()
    app.use('*', createRateLimiter(2, 60_000))
    app.get('/', c => c.json({ ok: true }))
    await app.request('/', { headers: { 'x-forwarded-for': '1.2.3.4' } })
    await app.request('/', { headers: { 'x-forwarded-for': '1.2.3.4' } })
    const res = await app.request('/', { headers: { 'x-forwarded-for': '1.2.3.4' } })
    expect(res.status).toBe(429)
  })
})

describe('security headers', () => {
  test('adds required OWASP security headers', async () => {
    const app = new Hono()
    app.use('*', securityHeadersMiddleware)
    app.get('/', c => c.json({ ok: true }))
    const res = await app.request('/')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('strict-transport-security')).toBeTruthy()
    expect(res.headers.get('cache-control')).toBe('no-store')
  })
})
```

- [ ] **Step 2: Run — expect FAIL**

```bash
bun test tests/unit/middleware/security.test.ts
```

- [ ] **Step 3: Implement rate-limit.ts**

```typescript
// src/shared/middleware/rate-limit.ts
import type { Context, Next } from 'hono'
import { Errors } from '../errors.js'

const store = new Map<string, { count: number; resetAt: number }>()

export function createRateLimiter(maxRequests: number, windowMs: number) {
  return async (c: Context, next: Next) => {
    const ip = c.req.header('x-forwarded-for') ?? c.req.header('x-real-ip') ?? 'unknown'
    const now = Date.now()
    const entry = store.get(ip)

    if (!entry || entry.resetAt < now) {
      store.set(ip, { count: 1, resetAt: now + windowMs })
      return next()
    }
    if (entry.count >= maxRequests) {
      const err = Errors.RATE_LIMITED()
      return c.json({ error: err.code, message: err.message, status: 429 }, 429)
    }
    entry.count++
    return next()
  }
}
```

- [ ] **Step 4: Implement security-headers.ts**

```typescript
// src/shared/middleware/security-headers.ts
import type { Context, Next } from 'hono'

export async function securityHeadersMiddleware(c: Context, next: Next) {
  await next()
  c.res.headers.set('X-Content-Type-Options', 'nosniff')
  c.res.headers.set('X-Frame-Options', 'DENY')
  c.res.headers.set('X-XSS-Protection', '1; mode=block')
  c.res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  c.res.headers.set('Content-Security-Policy', "default-src 'none'")
  c.res.headers.set('Cache-Control', 'no-store')
  c.res.headers.set('Referrer-Policy', 'no-referrer')
}
```

- [ ] **Step 5: Implement cors.ts**

```typescript
// src/shared/middleware/cors.ts
import { cors } from 'hono/cors'

const origin = process.env.CORS_ORIGIN ?? 'http://localhost:3000'

export const corsMiddleware = cors({
  origin,
  allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  exposeHeaders: ['Content-Type'],
  maxAge: 600,
  credentials: false,
})
```

- [ ] **Step 6: Run — expect PASS**

```bash
bun test tests/unit/middleware/security.test.ts
```

- [ ] **Step 7: Commit**

```bash
git add src/shared/middleware/ tests/unit/middleware/
git commit -m "feat: rate limiting, security headers, CORS middleware"
```

---

## Task 10: Auth Domain

**Files:**
- Create: `src/domains/auth/repository.ts`
- Create: `src/domains/auth/service.ts`
- Create: `src/domains/auth/middleware.ts`
- Create: `src/domains/auth/routes.ts`
- Create: `tests/integration/auth.test.ts`

- [ ] **Step 1: Write failing integration test**

```typescript
// tests/integration/auth.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { sql, runMigrations } from '../../src/shared/db'
import app from '../../src/index'

beforeAll(async () => {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL!
  process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
  process.env.JWT_SECRET = 'test-secret'
  await runMigrations()
  await sql`DELETE FROM auth_challenges`
  await sql`DELETE FROM sessions`
})

afterAll(async () => { await sql.end() })

describe('POST /v1/auth/challenge', () => {
  test('returns 400 when did is missing', async () => {
    const res = await app.request('/v1/auth/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  test('returns challengeId and nonce for a known DID', async () => {
    // First create a DID
    const createRes = await app.request('/v1/dids', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'subject' }),
    })
    const { did } = await createRes.json()

    const res = await app.request('/v1/auth/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.challengeId).toBeTruthy()
    expect(body.nonce).toBeTruthy()
  })
})
```

- [ ] **Step 2: Run — expect FAIL (index.ts not created yet, that's expected)**

```bash
bun test tests/integration/auth.test.ts 2>&1 | head -5
```

- [ ] **Step 3: Implement auth/repository.ts**

```typescript
// src/domains/auth/repository.ts
import { sql } from '../../shared/db.js'

export async function createChallenge(did: string, nonce: string): Promise<string> {
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 min
  const [row] = await sql`
    INSERT INTO auth_challenges (did, nonce, expires_at)
    VALUES (${did}, ${nonce}, ${expiresAt})
    RETURNING id
  `
  return row.id
}

export async function consumeChallenge(
  challengeId: string,
  did: string
): Promise<string | null> {
  const [row] = await sql`
    UPDATE auth_challenges
    SET used = true
    WHERE id = ${challengeId}
      AND did = ${did}
      AND used = false
      AND expires_at > now()
    RETURNING nonce
  `
  return row?.nonce ?? null
}

export async function createSession(did: string, role: string, token: string): Promise<void> {
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000) // 15 min
  await sql`
    INSERT INTO sessions (did, role, token, expires_at)
    VALUES (${did}, ${role}, ${token}, ${expiresAt})
  `
}
```

- [ ] **Step 4: Implement auth/service.ts**

```typescript
// src/domains/auth/service.ts
import { SignJWT, jwtVerify } from 'jose'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { createChallenge, consumeChallenge, createSession } from './repository.js'
import { sql } from '../../shared/db.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'
import type { Role } from '../../shared/types.js'

export async function requestChallenge(did: string): Promise<{ challengeId: string; nonce: string }> {
  const nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url')
  const challengeId = await createChallenge(did, nonce)
  return { challengeId, nonce }
}

export async function verifyChallenge(
  did: string,
  challengeId: string,
  signatureBase64: string
): Promise<string> {
  const nonce = await consumeChallenge(challengeId, did)
  if (!nonce) throw Errors.CHALLENGE_EXPIRED()

  const [row] = await sql`SELECT public_key, role FROM dids WHERE id = ${did} AND deactivated_at IS NULL`
  if (!row) throw Errors.DID_NOT_FOUND(did)

  const keyPair = await Ed25519VerificationKey2020.from({
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: row.publicKey,
  })
  const verifier = keyPair.verifier()
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const signature = Buffer.from(signatureBase64, 'base64')
  const valid = await verifier.verify({ data: message, signature })
  if (!valid) {
    await writeAuditLog(did, 'auth', 'failure')
    throw Errors.INVALID_PROOF()
  }

  const token = await issueJwt(did, row.role)
  await createSession(did, row.role, token)
  await writeAuditLog(did, 'auth', 'success')
  return token
}

export async function issueJwt(did: string, role: Role): Promise<string> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  return new SignJWT({ did, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setExpirationTime('15m')
    .setIssuedAt()
    .sign(secret)
}

export async function verifyJwt(token: string): Promise<{ did: string; role: Role }> {
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!)
  const { payload } = await jwtVerify(token, secret)
  return { did: payload.did as string, role: payload.role as Role }
}
```

- [ ] **Step 5: Implement auth/middleware.ts**

```typescript
// src/domains/auth/middleware.ts
import type { Context, Next } from 'hono'
import { verifyJwt } from './service.js'
import { Errors } from '../../shared/errors.js'
import type { Role } from '../../shared/types.js'

export async function jwtMiddleware(c: Context, next: Next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    const err = Errors.CHALLENGE_EXPIRED()
    return c.json({ error: 'UNAUTHORIZED', message: 'Missing Authorization header', status: 401 }, 401)
  }
  try {
    const payload = await verifyJwt(auth.slice(7))
    c.set('did', payload.did)
    c.set('role', payload.role)
    return next()
  } catch {
    return c.json({ error: 'UNAUTHORIZED', message: 'Invalid or expired token', status: 401 }, 401)
  }
}

export function requireRole(...roles: Role[]) {
  return async (c: Context, next: Next) => {
    const role = c.get('role') as Role
    if (!roles.includes(role)) {
      const err = Errors.UNAUTHORIZED_ROLE()
      return c.json({ error: err.code, message: err.message, status: 403 }, 403)
    }
    return next()
  }
}

export function requireOwner(getOwnerId: (c: Context) => Promise<string>) {
  return async (c: Context, next: Next) => {
    const callerDid = c.get('did') as string
    const ownerId = await getOwnerId(c)
    if (callerDid !== ownerId) {
      const err = Errors.FORBIDDEN()
      return c.json({ error: err.code, message: err.message, status: 403 }, 403)
    }
    return next()
  }
}
```

- [ ] **Step 6: Implement auth/routes.ts**

```typescript
// src/domains/auth/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { requestChallenge, verifyChallenge } from './service.js'
import { AppError } from '../../shared/errors.js'
import type { HonoVariables } from '../../shared/types.js'

export const authRouter = new Hono<{ Variables: HonoVariables }>()

const ChallengeSchema = z.object({ did: z.string().min(1) })
const VerifySchema = z.object({
  did: z.string().min(1),
  challengeId: z.string().uuid(),
  signature: z.string().min(1),
})

authRouter.post('/challenge', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = ChallengeSchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const result = await requestChallenge(parsed.data.did)
  return c.json(result)
})

authRouter.post('/verify', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = VerifySchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const token = await verifyChallenge(parsed.data.did, parsed.data.challengeId, parsed.data.signature)
  return c.json({ token })
})
```

- [ ] **Step 7: Commit (routes will be wired in Task 15)**

```bash
git add src/domains/auth/
git commit -m "feat: auth domain (challenge/verify/JWT/middleware)"
```

---

## Task 11: DID Domain

**Files:**
- Create: `src/domains/did/repository.ts`
- Create: `src/domains/did/service.ts`
- Create: `src/domains/did/routes.ts`

- [ ] **Step 1: Implement did/repository.ts**

```typescript
// src/domains/did/repository.ts
import { sql } from '../../shared/db.js'
import type { DidRecord } from '../../shared/types.js'

export async function insertDid(record: Omit<DidRecord, 'createdAt' | 'deactivatedAt'>): Promise<void> {
  await sql`
    INSERT INTO dids (id, role, document, public_key, private_key, bls_public_key, bls_private_key)
    VALUES (
      ${record.id}, ${record.role}, ${JSON.stringify(record.document)},
      ${record.publicKey}, ${record.privateKey},
      ${record.blsPublicKey ?? null}, ${record.blsPrivateKey ?? null}
    )
  `
}

export async function findDid(id: string): Promise<DidRecord | null> {
  const [row] = await sql`
    SELECT id, role, document, public_key, private_key,
           bls_public_key, bls_private_key, created_at, deactivated_at
    FROM dids WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id,
    role: row.role,
    document: row.document,
    publicKey: row.publicKey,
    privateKey: row.privateKey,
    blsPublicKey: row.blsPublicKey,
    blsPrivateKey: row.blsPrivateKey,
    createdAt: row.createdAt,
    deactivatedAt: row.deactivatedAt,
  }
}

export async function deactivateDid(id: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE dids SET deactivated_at = now()
    WHERE id = ${id} AND deactivated_at IS NULL
    RETURNING id
  `
  return !!row
}
```

- [ ] **Step 2: Implement did/service.ts**

```typescript
// src/domains/did/service.ts
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../shared/crypto/did-key.js'
import { encryptKey } from '../../shared/crypto/keys.js'
import { insertDid, findDid, deactivateDid } from './repository.js'
import { Errors } from '../../shared/errors.js'
import type { Role } from '../../shared/types.js'

export async function createDid(role: Role) {
  const { did, publicKeyMultibase, privateKeyMultibase } = await generateDidKey()
  const encryptedPrivateKey = await encryptKey(privateKeyMultibase)

  let blsPublicKey: string | null = null
  let blsPrivateKey: string | null = null
  let document: Record<string, unknown>

  if (role === 'issuer') {
    const bls = await generateBlsKeyPair(did)
    blsPublicKey = bls.publicKeyMultibase
    blsPrivateKey = await encryptKey(bls.secretKeyMultibase)
    document = buildDidDocument(did, publicKeyMultibase, blsPublicKey)
  } else {
    document = buildDidDocument(did, publicKeyMultibase)
  }

  await insertDid({
    id: did,
    role,
    document,
    publicKey: publicKeyMultibase,
    privateKey: encryptedPrivateKey,
    blsPublicKey,
    blsPrivateKey,
  })

  return {
    did,
    role,
    document,
    privateKey: privateKeyMultibase, // returned once only
  }
}

export async function resolveDid(id: string) {
  const record = await findDid(id)
  if (!record || record.deactivatedAt) throw Errors.DID_NOT_FOUND(id)
  return record.document
}

export async function getDidRecord(id: string) {
  const record = await findDid(id)
  if (!record || record.deactivatedAt) throw Errors.DID_NOT_FOUND(id)
  return record
}

export async function deactivate(id: string, callerDid: string) {
  if (id !== callerDid) throw Errors.FORBIDDEN()
  const ok = await deactivateDid(id)
  if (!ok) throw Errors.DID_NOT_FOUND(id)
}
```

- [ ] **Step 3: Implement did/routes.ts**

```typescript
// src/domains/did/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { createDid, resolveDid, getDidRecord, deactivate } from './service.js'
import { jwtMiddleware } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const didRouter = new Hono<{ Variables: HonoVariables }>()

const CreateDidSchema = z.object({
  role: z.enum(['subject', 'issuer', 'verifier', 'attester']),
})

// Public — create DID
didRouter.post('/', async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = CreateDidSchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const result = await createDid(parsed.data.role)
  return c.json(result, 201)
})

// Protected — get own DID (must be before /:did)
didRouter.get('/me', jwtMiddleware, async c => {
  const did = c.get('did')
  const document = await resolveDid(did)
  return c.json({ did, document })
})

// Public — resolve DID
didRouter.get('/:did', async c => {
  const document = await resolveDid(c.req.param('did'))
  return c.json({ document })
})

// Protected — deactivate DID (owner only)
didRouter.delete('/:did', jwtMiddleware, async c => {
  const callerDid = c.get('did')
  await deactivate(c.req.param('did'), callerDid)
  return c.json({ success: true })
})
```

- [ ] **Step 4: Commit**

```bash
git add src/domains/did/
git commit -m "feat: DID domain (create, resolve, deactivate)"
```

---

## Task 12: Trust Domain

**Files:**
- Create: `src/domains/trust/repository.ts`
- Create: `src/domains/trust/service.ts`
- Create: `src/domains/trust/routes.ts`

- [ ] **Step 1: Implement trust/repository.ts**

```typescript
// src/domains/trust/repository.ts
import { sql } from '../../shared/db.js'
import type { TrustAttestationRecord } from '../../shared/types.js'

export async function insertAttestation(record: Omit<TrustAttestationRecord, 'issuedAt'>): Promise<void> {
  await sql`
    INSERT INTO trust_attestations (id, attester_did, issuer_did, credential, status, expires_at)
    VALUES (
      ${record.id}, ${record.attesterDid}, ${record.issuerDid},
      ${JSON.stringify(record.credential)}, ${record.status}, ${record.expiresAt ?? null}
    )
  `
}

export async function findActiveAttestation(issuerDid: string): Promise<TrustAttestationRecord | null> {
  const [row] = await sql`
    SELECT id, attester_did, issuer_did, credential, status, issued_at, expires_at
    FROM trust_attestations
    WHERE issuer_did = ${issuerDid}
      AND status = 'active'
      AND (expires_at IS NULL OR expires_at > now())
    ORDER BY issued_at DESC LIMIT 1
  `
  if (!row) return null
  return {
    id: row.id,
    attesterDid: row.attesterDid,
    issuerDid: row.issuerDid,
    credential: row.credential,
    status: row.status,
    issuedAt: row.issuedAt,
    expiresAt: row.expiresAt,
  }
}

export async function listTrustedIssuers(): Promise<{ issuerDid: string; attesterDid: string; issuedAt: Date }[]> {
  return sql`
    SELECT DISTINCT ON (issuer_did)
      issuer_did, attester_did, issued_at
    FROM trust_attestations
    WHERE status = 'active' AND (expires_at IS NULL OR expires_at > now())
    ORDER BY issuer_did, issued_at DESC
  `
}

export async function revokeAttestation(id: string, attesterDid: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE trust_attestations SET status = 'revoked'
    WHERE id = ${id} AND attester_did = ${attesterDid} AND status = 'active'
    RETURNING id
  `
  return !!row
}
```

- [ ] **Step 2: Implement trust/service.ts**

```typescript
// src/domains/trust/service.ts
import { randomUUID } from 'crypto'
import { insertAttestation, findActiveAttestation, listTrustedIssuers, revokeAttestation } from './repository.js'
import { getDidRecord } from '../did/service.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'

export async function attestIssuer(
  attesterDid: string,
  issuerDid: string,
  expiresAt?: Date
) {
  // Verify both DIDs exist
  await getDidRecord(attesterDid)
  await getDidRecord(issuerDid)

  const id = `urn:uuid:${randomUUID()}`
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    type: ['VerifiableCredential', 'IssuerAttestation'],
    issuer: attesterDid,
    credentialSubject: { id: issuerDid, isAuthorizedIssuer: true },
    ...(expiresAt ? { expirationDate: expiresAt.toISOString() } : {}),
  }
  await insertAttestation({ id, attesterDid, issuerDid, credential, status: 'active', expiresAt: expiresAt ?? null })
  await writeAuditLog(attesterDid, 'attest', 'success', id)
  return { id, credential }
}

export async function isIssuerTrusted(issuerDid: string): Promise<boolean> {
  const attestation = await findActiveAttestation(issuerDid)
  return attestation !== null
}

export async function getTrustedIssuers() {
  return listTrustedIssuers()
}

export async function revokeIssuerAttestation(id: string, attesterDid: string) {
  const ok = await revokeAttestation(id, attesterDid)
  if (!ok) throw Errors.ATTESTATION_NOT_FOUND(id)
  await writeAuditLog(attesterDid, 'revoke', 'success', id)
}
```

- [ ] **Step 3: Implement trust/routes.ts**

```typescript
// src/domains/trust/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { attestIssuer, getTrustedIssuers, isIssuerTrusted, revokeIssuerAttestation } from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const trustRouter = new Hono<{ Variables: HonoVariables }>()

const AttestSchema = z.object({
  issuerDid: z.string().min(1),
  expiresAt: z.string().datetime().optional(),
})

// Public reads
trustRouter.get('/issuers', async c => {
  const issuers = await getTrustedIssuers()
  return c.json({ issuers })
})

trustRouter.get('/issuers/:did', async c => {
  const trusted = await isIssuerTrusted(c.req.param('did'))
  return c.json({ trusted })
})

// Protected writes — attester only
trustRouter.post('/attest', jwtMiddleware, requireRole('attester'), async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = AttestSchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const attesterDid = c.get('did')
  const expiresAt = parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : undefined
  const result = await attestIssuer(attesterDid, parsed.data.issuerDid, expiresAt)
  return c.json(result, 201)
})

trustRouter.post('/attest/:id/revoke', jwtMiddleware, requireRole('attester'), async c => {
  await revokeIssuerAttestation(c.req.param('id'), c.get('did'))
  return c.json({ success: true })
})
```

- [ ] **Step 4: Commit**

```bash
git add src/domains/trust/
git commit -m "feat: trust registry domain (attest, list, revoke)"
```

---

## Task 13: Credentials Domain

**Files:**
- Create: `src/domains/credentials/repository.ts`
- Create: `src/domains/credentials/service.ts`
- Create: `src/domains/credentials/routes.ts`

- [ ] **Step 1: Implement credentials/repository.ts**

```typescript
// src/domains/credentials/repository.ts
import { sql } from '../../shared/db.js'
import type { CredentialRecord } from '../../shared/types.js'

export async function insertCredential(record: Omit<CredentialRecord, 'issuedAt'>): Promise<void> {
  await sql`
    INSERT INTO credentials (id, issuer_did, subject_did, type, claims, document, status, expires_at)
    VALUES (
      ${record.id}, ${record.issuerDid}, ${record.subjectDid},
      ${record.type}, ${JSON.stringify(record.claims)},
      ${JSON.stringify(record.document)}, ${record.status}, ${record.expiresAt ?? null}
    )
  `
}

export async function findCredential(id: string): Promise<CredentialRecord | null> {
  const [row] = await sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at
    FROM credentials WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id, issuerDid: row.issuerDid, subjectDid: row.subjectDid,
    type: row.type, claims: row.claims, document: row.document,
    status: row.status, issuedAt: row.issuedAt, expiresAt: row.expiresAt,
  }
}

export async function listCredentialsByIssuer(issuerDid: string): Promise<CredentialRecord[]> {
  return sql`
    SELECT id, issuer_did, subject_did, type, claims, document, status, issued_at, expires_at
    FROM credentials WHERE issuer_did = ${issuerDid}
    ORDER BY issued_at DESC
  `
}

export async function revokeCredential(id: string, issuerDid: string): Promise<boolean> {
  const [row] = await sql`
    UPDATE credentials SET status = 'revoked'
    WHERE id = ${id} AND issuer_did = ${issuerDid} AND status = 'active'
    RETURNING id
  `
  return !!row
}
```

- [ ] **Step 2: Implement credentials/service.ts**

```typescript
// src/domains/credentials/service.ts
import { randomUUID } from 'crypto'
import { Bbs2023Multikey } from '@digitalbazaar/bbs-cryptosuite-2023'
import { signCredential } from '../../shared/crypto/bbs.js'
import { decryptKey } from '../../shared/crypto/keys.js'
import { isIssuerTrusted } from '../trust/service.js'
import { getDidRecord } from '../did/service.js'
import { insertCredential, findCredential, listCredentialsByIssuer, revokeCredential } from './repository.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'

export async function issueCredential(
  issuerDid: string,
  subjectDid: string,
  credentialType: string[],
  claims: Record<string, unknown>,
  expiresAt?: Date
) {
  if (!(await isIssuerTrusted(issuerDid))) throw Errors.ISSUER_NOT_TRUSTED()

  const issuerRecord = await getDidRecord(issuerDid)
  if (!issuerRecord.blsPublicKey || !issuerRecord.blsPrivateKey) {
    throw new Error('Issuer does not have a BLS12-381 key')
  }
  await getDidRecord(subjectDid) // validates subject exists

  const secretKeyMultibase = await decryptKey(issuerRecord.blsPrivateKey)
  const keyPair = await Bbs2023Multikey.from({
    id: `${issuerDid}#${issuerRecord.blsPublicKey}`,
    controller: issuerDid,
    publicKeyMultibase: issuerRecord.blsPublicKey,
    secretKeyMultibase,
  })

  const id = `urn:uuid:${randomUUID()}`
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    type: ['VerifiableCredential', ...credentialType],
    issuer: issuerDid,
    credentialSubject: { id: subjectDid, ...claims },
    ...(expiresAt ? { expirationDate: expiresAt.toISOString() } : {}),
  }

  const signedVc = await signCredential(credential, keyPair)
  await insertCredential({
    id, issuerDid, subjectDid,
    type: ['VerifiableCredential', ...credentialType],
    claims, document: signedVc as Record<string, unknown>,
    status: 'active', expiresAt: expiresAt ?? null,
  })
  await writeAuditLog(issuerDid, 'issue', 'success', id)
  return signedVc
}

export async function getCredential(id: string, callerDid: string) {
  const record = await findCredential(id)
  if (!record) throw Errors.CREDENTIAL_NOT_FOUND(id)
  if (record.issuerDid !== callerDid && record.subjectDid !== callerDid) throw Errors.FORBIDDEN()
  return record
}

export async function listCredentials(issuerDid: string) {
  return listCredentialsByIssuer(issuerDid)
}

export async function revokeCredentialById(id: string, issuerDid: string) {
  const ok = await revokeCredential(id, issuerDid)
  if (!ok) throw Errors.CREDENTIAL_NOT_FOUND(id)
  await writeAuditLog(issuerDid, 'revoke', 'success', id)
}

export async function getCredentialStatus(id: string) {
  const record = await findCredential(id)
  if (!record) throw Errors.CREDENTIAL_NOT_FOUND(id)
  return { id, status: record.status }
}
```

- [ ] **Step 3: Implement credentials/routes.ts**

```typescript
// src/domains/credentials/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { issueCredential, getCredential, listCredentials, revokeCredentialById, getCredentialStatus } from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import { createRateLimiter } from '../../shared/middleware/rate-limit.js'
import type { HonoVariables } from '../../shared/types.js'

export const credentialsRouter = new Hono<{ Variables: HonoVariables }>()

const IssueSchema = z.object({
  subjectDid: z.string().min(1),
  credentialType: z.array(z.string()).min(1),
  claims: z.record(z.unknown()),
  expiresAt: z.string().datetime().optional(),
})

// Public
credentialsRouter.get('/:id/status', getCredentialStatus)

// Protected
credentialsRouter.post(
  '/issue',
  jwtMiddleware, requireRole('issuer'), createRateLimiter(10, 60_000),
  async c => {
    const body = await c.req.json().catch(() => ({}))
    const parsed = IssueSchema.safeParse(body)
    if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
    const { subjectDid, credentialType, claims, expiresAt } = parsed.data
    const vc = await issueCredential(
      c.get('did'), subjectDid, credentialType, claims,
      expiresAt ? new Date(expiresAt) : undefined
    )
    return c.json(vc, 201)
  }
)

credentialsRouter.get('/', jwtMiddleware, requireRole('issuer'), async c => {
  const records = await listCredentials(c.get('did'))
  return c.json({ credentials: records })
})

credentialsRouter.get('/:id', jwtMiddleware, async c => {
  const record = await getCredential(c.req.param('id'), c.get('did'))
  return c.json(record)
})

credentialsRouter.post('/:id/revoke', jwtMiddleware, requireRole('issuer'), async c => {
  await revokeCredentialById(c.req.param('id'), c.get('did'))
  return c.json({ success: true })
})
```

- [ ] **Step 4: Commit**

```bash
git add src/domains/credentials/
git commit -m "feat: credentials domain (issue, list, revoke, status)"
```

---

## Task 14: Presentation Domain

**Files:**
- Create: `src/domains/presentation/repository.ts`
- Create: `src/domains/presentation/service.ts`
- Create: `src/domains/presentation/routes.ts`

- [ ] **Step 1: Implement presentation/repository.ts**

```typescript
// src/domains/presentation/repository.ts
import { sql } from '../../shared/db.js'
import type { PresentationRecord } from '../../shared/types.js'

export async function insertPresentation(record: Omit<PresentationRecord, 'createdAt'>): Promise<void> {
  await sql`
    INSERT INTO presentations (id, holder_did, credential_ids, document, disclosed_claims)
    VALUES (
      ${record.id}, ${record.holderDid}, ${record.credentialIds},
      ${JSON.stringify(record.document)}, ${JSON.stringify(record.disclosedClaims)}
    )
  `
}

export async function findPresentation(id: string): Promise<PresentationRecord | null> {
  const [row] = await sql`
    SELECT id, holder_did, credential_ids, document, disclosed_claims, created_at
    FROM presentations WHERE id = ${id}
  `
  if (!row) return null
  return {
    id: row.id, holderDid: row.holderDid, credentialIds: row.credentialIds,
    document: row.document, disclosedClaims: row.disclosedClaims, createdAt: row.createdAt,
  }
}
```

- [ ] **Step 2: Implement presentation/service.ts**

```typescript
// src/domains/presentation/service.ts
import { randomUUID } from 'crypto'
import * as vc from '@digitalbazaar/vc'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'
import { deriveProof, verifyPresentation as bbsVerify } from '../../shared/crypto/bbs.js'
import { decryptKey } from '../../shared/crypto/keys.js'
import { getDidRecord } from '../did/service.js'
import { findCredential } from '../credentials/repository.js'
import { isIssuerTrusted } from '../trust/service.js'
import { insertPresentation, findPresentation } from './repository.js'
import { Errors } from '../../shared/errors.js'
import { writeAuditLog } from '../../shared/db.js'
import { getDocumentLoader } from '../../shared/jsonld/loader.js'

export async function deriveSelectivePresentation(
  holderDid: string,
  credentialId: string,
  revealedClaims: string[]
) {
  const credential = await findCredential(credentialId)
  if (!credential) throw Errors.CREDENTIAL_NOT_FOUND(credentialId)
  if (credential.subjectDid !== holderDid) throw Errors.FORBIDDEN()
  if (credential.status === 'revoked') throw Errors.CREDENTIAL_REVOKED()

  // Build JSON pointer paths for BBS+ selective disclosure
  const selectivePointers = revealedClaims.map(c => `/credentialSubject/${c}`)
  const derived = await deriveProof(credential.document, selectivePointers)

  // Holder-binding: sign VP envelope with Ed25519 key
  const holderRecord = await getDidRecord(holderDid)
  const privateKeyMultibase = await decryptKey(holderRecord.privateKey)
  const keyPair = await Ed25519VerificationKey2020.from({
    id: `${holderDid}#${holderRecord.publicKey}`,
    controller: holderDid,
    publicKeyMultibase: holderRecord.publicKey,
    privateKeyMultibase,
  })
  const holderSuite = new Ed25519Signature2020({ key: keyPair })
  const challenge = randomUUID()
  const presentation = vc.createPresentation({ verifiableCredential: derived, holder: holderDid })
  const signedVp = await vc.signPresentation({
    presentation, suite: holderSuite, challenge, documentLoader: getDocumentLoader(),
  })

  const id = `urn:uuid:${randomUUID()}`
  const disclosedClaims = Object.fromEntries(
    revealedClaims.map(k => [k, (credential.claims as Record<string, unknown>)[k]])
  )
  await insertPresentation({ id, holderDid, credentialIds: [credentialId], document: signedVp, disclosedClaims })
  await writeAuditLog(holderDid, 'issue', 'success', id)
  return { id, presentation: signedVp, disclosedClaims }
}

export async function verifyVp(
  presentationDoc: Record<string, unknown>,
  verifierDid: string
): Promise<{ valid: boolean; disclosedClaims: unknown; issuerTrusted: boolean; credentialStatus: string }> {
  // Extract issuer DID from the embedded VC
  const embeddedVc = (presentationDoc.verifiableCredential as any)?.[0] ?? presentationDoc.verifiableCredential
  const issuerDid = typeof embeddedVc?.issuer === 'string' ? embeddedVc.issuer : embeddedVc?.issuer?.id
  const credentialId = embeddedVc?.id

  const issuerTrusted = issuerDid ? await isIssuerTrusted(issuerDid) : false

  let credentialStatus = 'unknown'
  if (credentialId) {
    const record = await findCredential(credentialId)
    credentialStatus = record?.status ?? 'unknown'
  }
  if (credentialStatus === 'revoked') throw Errors.CREDENTIAL_REVOKED()

  const valid = await bbsVerify(presentationDoc)
  await writeAuditLog(verifierDid, 'verify', valid ? 'success' : 'failure')

  return {
    valid,
    disclosedClaims: embeddedVc?.credentialSubject ?? {},
    issuerTrusted,
    credentialStatus,
  }
}

export async function getPresentation(id: string, callerDid: string) {
  const record = await findPresentation(id)
  if (!record) throw Errors.PRESENTATION_NOT_FOUND(id)
  if (record.holderDid !== callerDid) throw Errors.FORBIDDEN()
  return record
}
```

- [ ] **Step 3: Implement presentation/routes.ts**

```typescript
// src/domains/presentation/routes.ts
import { Hono } from 'hono'
import { z } from 'zod'
import { deriveSelectivePresentation, verifyVp, getPresentation } from './service.js'
import { jwtMiddleware, requireRole } from '../auth/middleware.js'
import type { HonoVariables } from '../../shared/types.js'

export const presentationRouter = new Hono<{ Variables: HonoVariables }>()

const DeriveSchema = z.object({
  credentialId: z.string().min(1),
  revealedClaims: z.array(z.string()).min(1),
})

const VerifySchema = z.object({
  presentation: z.record(z.unknown()),
})

presentationRouter.post('/derive', jwtMiddleware, requireRole('subject'), async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = DeriveSchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const result = await deriveSelectivePresentation(c.get('did'), parsed.data.credentialId, parsed.data.revealedClaims)
  return c.json(result, 201)
})

presentationRouter.post('/verify', jwtMiddleware, requireRole('verifier'), async c => {
  const body = await c.req.json().catch(() => ({}))
  const parsed = VerifySchema.safeParse(body)
  if (!parsed.success) return c.json({ error: 'VALIDATION_ERROR', message: parsed.error.message, status: 400 }, 400)
  const result = await verifyVp(parsed.data.presentation, c.get('did'))
  return c.json(result)
})

presentationRouter.get('/:id', jwtMiddleware, requireRole('subject'), async c => {
  const record = await getPresentation(c.req.param('id'), c.get('did'))
  return c.json(record)
})
```

- [ ] **Step 4: Commit**

```bash
git add src/domains/presentation/
git commit -m "feat: presentation domain (derive, verify, fetch)"
```

---

## Task 15: Server Entry Point

**Files:**
- Create: `src/index.ts`

- [ ] **Step 1: Implement index.ts**

```typescript
// src/index.ts
import { Hono } from 'hono'
import { AppError } from './shared/errors.js'
import { runMigrations, sql } from './shared/db.js'
import { initContextLoader, setDidResolver } from './shared/jsonld/loader.js'
import { corsMiddleware } from './shared/middleware/cors.js'
import { securityHeadersMiddleware } from './shared/middleware/security-headers.js'
import { createRateLimiter } from './shared/middleware/rate-limit.js'
import { authRouter } from './domains/auth/routes.js'
import { didRouter } from './domains/did/routes.js'
import { credentialsRouter } from './domains/credentials/routes.js'
import { presentationRouter } from './domains/presentation/routes.js'
import { trustRouter } from './domains/trust/routes.js'
import type { HonoVariables } from './shared/types.js'

const app = new Hono<{ Variables: HonoVariables }>()

// Global middleware
app.use('*', corsMiddleware)
app.use('*', securityHeadersMiddleware)
app.use('*', createRateLimiter(100, 60_000))

// Body size limit (64KB)
app.use('*', async (c, next) => {
  const contentLength = c.req.header('content-length')
  if (contentLength && parseInt(contentLength) > 65536) {
    return c.json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body exceeds 64KB', status: 413 }, 413)
  }
  return next()
})

// Routes
app.route('/v1/auth', authRouter)
app.route('/v1/dids', didRouter)
app.route('/v1/credentials', credentialsRouter)
app.route('/v1/presentations', presentationRouter)
app.route('/v1/trust', trustRouter)

// Health check
app.get('/health', c => c.json({ status: 'ok' }))

// Global error handler
app.onError((err, c) => {
  if (err instanceof AppError) {
    return c.json({ error: err.code, message: err.message, status: err.status }, err.status as any)
  }
  console.error('[error]', err.message)
  return c.json({ error: 'INTERNAL_ERROR', message: 'An internal error occurred', status: 500 }, 500)
})

// Startup
await runMigrations()
await initContextLoader()

// Wire DID resolver into the JSON-LD document loader
const { findDid } = await import('./domains/did/repository.js')
setDidResolver(async (did: string) => {
  const record = await findDid(did)
  if (!record || record.deactivatedAt) throw new AppError('DID_NOT_FOUND', `DID ${did} not found`, 404)
  return record.document
})

export default {
  port: parseInt(process.env.PORT ?? '3000'),
  fetch: app.fetch,
}
```

- [ ] **Step 2: Create .env from example and start the server**

```bash
cp .env.example .env
# Edit .env: set DATABASE_URL to your local postgres, generate KEY_ENCRYPTION_SECRET and JWT_SECRET
openssl rand -hex 32  # use output as KEY_ENCRYPTION_SECRET
openssl rand -base64 32  # use output as JWT_SECRET
```

- [ ] **Step 3: Run the server**

```bash
bun run dev
```

Expected output:
```
[db] migrated: 001_init.sql
[db] migrated: 002_audit.sql
```

- [ ] **Step 4: Verify health endpoint**

```bash
curl http://localhost:3000/health
```

Expected: `{"status":"ok"}`

- [ ] **Step 5: Commit**

```bash
git add src/index.ts .env.example
git commit -m "feat: server entry point, route wiring, startup sequence"
```

---

## Task 16: Test Fixtures

**Files:**
- Create: `tests/fixtures/generate.ts`

- [ ] **Step 1: Implement generate.ts**

```typescript
// tests/fixtures/generate.ts
import { generateDidKey, generateBlsKeyPair, buildDidDocument } from '../../src/shared/crypto/did-key'
import { encryptKey } from '../../src/shared/crypto/keys'
import { writeFile } from 'fs/promises'
import { join } from 'path'

process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)

async function generateFixture(role: string, withBls = false) {
  const { did, publicKeyMultibase, privateKeyMultibase } = await generateDidKey()
  let blsPublicKey: string | undefined
  let blsSecretKey: string | undefined
  if (withBls) {
    const bls = await generateBlsKeyPair(did)
    blsPublicKey = bls.publicKeyMultibase
    blsSecretKey = bls.secretKeyMultibase
  }
  const document = buildDidDocument(did, publicKeyMultibase, blsPublicKey)
  return { did, role, document, publicKeyMultibase, privateKeyMultibase, blsPublicKey, blsSecretKey }
}

const issuer = await generateFixture('issuer', true)
const subject = await generateFixture('subject')
const attester = await generateFixture('attester')
const verifier = await generateFixture('verifier')

const dir = join(import.meta.dir)
await writeFile(join(dir, 'issuer-did.json'), JSON.stringify(issuer, null, 2))
await writeFile(join(dir, 'subject-did.json'), JSON.stringify(subject, null, 2))
await writeFile(join(dir, 'attester-did.json'), JSON.stringify(attester, null, 2))
await writeFile(join(dir, 'verifier-did.json'), JSON.stringify(verifier, null, 2))

console.log('Fixtures generated.')
```

- [ ] **Step 2: Run generator**

```bash
bun run tests/fixtures/generate.ts
```

Expected: four JSON files created in `tests/fixtures/`.

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/generate.ts tests/fixtures/*.json
git commit -m "test: generate DID fixtures"
```

---

## Task 17: Integration — Full Lifecycle Test

**Files:**
- Create: `tests/integration/lifecycle.test.ts`

- [ ] **Step 1: Write lifecycle test**

```typescript
// tests/integration/lifecycle.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { sql, runMigrations } from '../../src/shared/db'
import app from '../../src/index'

beforeAll(async () => {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL!
  process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
  process.env.JWT_SECRET = 'test-secret'
  await runMigrations()
  // Clean test data
  await sql`DELETE FROM presentations`
  await sql`DELETE FROM credentials`
  await sql`DELETE FROM trust_attestations`
  await sql`DELETE FROM auth_challenges`
  await sql`DELETE FROM sessions`
  await sql`DELETE FROM dids`
})

afterAll(async () => { await sql.end() })

async function createAndAuth(role: string): Promise<{ did: string; token: string; privateKeyMultibase: string }> {
  // 1. Create DID
  const createRes = await app.request('/v1/dids', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  })
  expect(createRes.status).toBe(201)
  const { did, privateKey: privateKeyMultibase } = await createRes.json()

  // 2. Get challenge
  const chalRes = await app.request('/v1/auth/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  })
  expect(chalRes.status).toBe(200)
  const { challengeId, nonce } = await chalRes.json()

  // 3. Sign nonce with Ed25519 private key
  const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020')
  const keyPair = await Ed25519VerificationKey2020.from({
    type: 'Ed25519VerificationKey2020',
    privateKeyMultibase,
    publicKeyMultibase: did.replace('did:key:', ''),
  })
  const signer = keyPair.signer()
  const message = new TextEncoder().encode(`${did}:${nonce}`)
  const signatureBytes = await signer.sign({ data: message })
  const signature = Buffer.from(signatureBytes).toString('base64')

  // 4. Verify and get token
  const verifyRes = await app.request('/v1/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature }),
  })
  expect(verifyRes.status).toBe(200)
  const { token } = await verifyRes.json()

  return { did, token, privateKeyMultibase }
}

describe('Full DID+VC+VP lifecycle', () => {
  let attesterDid: string, attesterToken: string
  let issuerDid: string, issuerToken: string
  let subjectDid: string, subjectToken: string
  let verifierDid: string, verifierToken: string
  let credentialId: string
  let presentationId: string

  test('1. Register all actors', async () => {
    ;({ did: attesterDid, token: attesterToken } = await createAndAuth('attester'))
    ;({ did: issuerDid, token: issuerToken } = await createAndAuth('issuer'))
    ;({ did: subjectDid, token: subjectToken } = await createAndAuth('subject'))
    ;({ did: verifierDid, token: verifierToken } = await createAndAuth('verifier'))
    expect(attesterDid).toMatch(/^did:key:/)
    expect(issuerDid).toMatch(/^did:key:/)
  })

  test('2. Attester vouches for issuer', async () => {
    const res = await app.request('/v1/trust/attest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    })
    expect(res.status).toBe(201)
  })

  test('3. Trust registry shows issuer as trusted', async () => {
    const res = await app.request(`/v1/trust/issuers/${issuerDid}`)
    expect(res.status).toBe(200)
    expect((await res.json()).trusted).toBe(true)
  })

  test('4. Issuer issues a VC to subject', async () => {
    const res = await app.request('/v1/credentials/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({
        subjectDid,
        credentialType: ['UniversityDegree'],
        claims: { name: 'Alice', degree: 'BSc Computer Science', gpa: '3.9' },
      }),
    })
    expect(res.status).toBe(201)
    const body = await res.json()
    credentialId = body.id
    expect(credentialId).toBeTruthy()
    expect(body.proof?.type).toBe('DataIntegrityProof')
  })

  test('5. Subject derives a VP revealing only name and degree', async () => {
    const res = await app.request('/v1/presentations/derive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${subjectToken}` },
      body: JSON.stringify({ credentialId, revealedClaims: ['name', 'degree'] }),
    })
    expect(res.status).toBe(201)
    const body = await res.json()
    presentationId = body.id
    expect(body.disclosedClaims.name).toBe('Alice')
    expect(body.disclosedClaims.degree).toBeTruthy()
    expect(body.disclosedClaims.gpa).toBeUndefined()
  })

  test('6. Verifier verifies the VP', async () => {
    const vpRes = await app.request(`/v1/presentations/${presentationId}`, {
      headers: { Authorization: `Bearer ${subjectToken}` },
    })
    const { document } = await vpRes.json()

    const res = await app.request('/v1/presentations/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${verifierToken}` },
      body: JSON.stringify({ presentation: document }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.valid).toBe(true)
    expect(body.issuerTrusted).toBe(true)
    expect(body.credentialStatus).toBe('active')
  })
})
```

- [ ] **Step 2: Run**

```bash
bun test tests/integration/lifecycle.test.ts
```

Expected: all 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/lifecycle.test.ts
git commit -m "test: full DID+VC+VP lifecycle integration test"
```

---

## Task 18: Integration — Revocation & Trust Paths

**Files:**
- Create: `tests/integration/revocation.test.ts`

- [ ] **Step 1: Write revocation and trust path tests**

```typescript
// tests/integration/revocation.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { sql, runMigrations } from '../../src/shared/db'
import app from '../../src/index'

// re-use createAndAuth helper from lifecycle test
async function createAndAuth(role: string) {
  const createRes = await app.request('/v1/dids', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  })
  const { did, privateKey: privateKeyMultibase } = await createRes.json()
  const chalRes = await app.request('/v1/auth/challenge', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did }),
  })
  const { challengeId, nonce } = await chalRes.json()
  const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020')
  const keyPair = await Ed25519VerificationKey2020.from({
    type: 'Ed25519VerificationKey2020', privateKeyMultibase,
    publicKeyMultibase: did.replace('did:key:', ''),
  })
  const sig = await keyPair.signer().sign({ data: new TextEncoder().encode(`${did}:${nonce}`) })
  const signature = Buffer.from(sig).toString('base64')
  const verifyRes = await app.request('/v1/auth/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ did, challengeId, signature }),
  })
  const { token } = await verifyRes.json()
  return { did, token }
}

beforeAll(async () => {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL!
  process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
  process.env.JWT_SECRET = 'test-secret'
  await runMigrations()
  await sql`DELETE FROM presentations`
  await sql`DELETE FROM credentials`
  await sql`DELETE FROM trust_attestations`
  await sql`DELETE FROM auth_challenges`
  await sql`DELETE FROM sessions`
  await sql`DELETE FROM dids`
})

afterAll(async () => { await sql.end() })

describe('Credential revocation', () => {
  test('verification fails on a revoked credential', async () => {
    const { did: attesterDid, token: attesterToken } = await createAndAuth('attester')
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid, token: subjectToken } = await createAndAuth('subject')
    const { did: verifierDid, token: verifierToken } = await createAndAuth('verifier')

    await app.request('/v1/trust/attest', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    })

    const issueRes = await app.request('/v1/credentials/issue', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Bob' } }),
    })
    const { id: credentialId } = await issueRes.json()

    // Revoke
    const revokeRes = await app.request(`/v1/credentials/${credentialId}/revoke`, {
      method: 'POST', headers: { Authorization: `Bearer ${issuerToken}` },
    })
    expect(revokeRes.status).toBe(200)

    // Status endpoint returns revoked
    const statusRes = await app.request(`/v1/credentials/${credentialId}/status`)
    expect((await statusRes.json()).status).toBe('revoked')

    // Derive should fail
    const deriveRes = await app.request('/v1/presentations/derive', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${subjectToken}` },
      body: JSON.stringify({ credentialId, revealedClaims: ['name'] }),
    })
    expect(deriveRes.status).toBe(422)
    expect((await deriveRes.json()).error).toBe('CREDENTIAL_REVOKED')
  })
})

describe('Trust path enforcement', () => {
  test('issuance fails when issuer has no attestation', async () => {
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid } = await createAndAuth('subject')

    const res = await app.request('/v1/credentials/issue', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Carol' } }),
    })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('ISSUER_NOT_TRUSTED')
  })

  test('issuance succeeds after attestation is granted', async () => {
    const { did: attesterDid, token: attesterToken } = await createAndAuth('attester')
    const { did: issuerDid, token: issuerToken } = await createAndAuth('issuer')
    const { did: subjectDid } = await createAndAuth('subject')

    await app.request('/v1/trust/attest', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` },
      body: JSON.stringify({ issuerDid }),
    })

    const res = await app.request('/v1/credentials/issue', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` },
      body: JSON.stringify({ subjectDid, credentialType: ['TestCred'], claims: { name: 'Carol' } }),
    })
    expect(res.status).toBe(201)
  })
})
```

- [ ] **Step 2: Run**

```bash
bun test tests/integration/revocation.test.ts
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/revocation.test.ts
git commit -m "test: revocation and trust path integration tests"
```

---

## Task 19: Security Tests (OWASP)

**Files:**
- Create: `tests/security/owasp.test.ts`

- [ ] **Step 1: Write security tests**

```typescript
// tests/security/owasp.test.ts
import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { sql, runMigrations } from '../../src/shared/db'
import app from '../../src/index'

beforeAll(async () => {
  process.env.DATABASE_URL = process.env.TEST_DATABASE_URL!
  process.env.KEY_ENCRYPTION_SECRET = 'a'.repeat(64)
  process.env.JWT_SECRET = 'test-secret'
  await runMigrations()
})

afterAll(async () => { await sql.end() })

describe('API2 — Broken Authentication', () => {
  test('replaying a used nonce returns CHALLENGE_EXPIRED', async () => {
    const createRes = await app.request('/v1/dids', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'subject' }),
    })
    const { did, privateKey: privateKeyMultibase } = await createRes.json()
    const chalRes = await app.request('/v1/auth/challenge', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ did }),
    })
    const { challengeId, nonce } = await chalRes.json()
    const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020')
    const kp = await Ed25519VerificationKey2020.from({ type: 'Ed25519VerificationKey2020', privateKeyMultibase, publicKeyMultibase: did.replace('did:key:', '') })
    const sig = Buffer.from(await kp.signer().sign({ data: new TextEncoder().encode(`${did}:${nonce}`) })).toString('base64')
    const payload = JSON.stringify({ did, challengeId, signature: sig })
    // First use succeeds
    const first = await app.request('/v1/auth/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload })
    expect(first.status).toBe(200)
    // Second use fails
    const second = await app.request('/v1/auth/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload })
    expect(second.status).toBe(401)
    expect((await second.json()).error).toBe('CHALLENGE_EXPIRED')
  })
})

describe('API1 — Broken Object Level Authorization', () => {
  test('subject cannot read another subject credential', async () => {
    // Create two subjects and an issuer+attester, issue to subject1, try to read as subject2
    const createDid = async (role: string) => {
      const res = await app.request('/v1/dids', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role }) })
      return res.json()
    }
    const auth = async (did: string, priv: string) => {
      const chalRes = await app.request('/v1/auth/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ did }) })
      const { challengeId, nonce } = await chalRes.json()
      const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020')
      const kp = await Ed25519VerificationKey2020.from({ type: 'Ed25519VerificationKey2020', privateKeyMultibase: priv, publicKeyMultibase: did.replace('did:key:', '') })
      const sig = Buffer.from(await kp.signer().sign({ data: new TextEncoder().encode(`${did}:${nonce}`) })).toString('base64')
      const vr = await app.request('/v1/auth/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ did, challengeId, signature: sig }) })
      return (await vr.json()).token
    }
    const attesterData = await createDid('attester')
    const issuerData = await createDid('issuer')
    const sub1Data = await createDid('subject')
    const sub2Data = await createDid('subject')
    const attesterToken = await auth(attesterData.did, attesterData.privateKey)
    const issuerToken = await auth(issuerData.did, issuerData.privateKey)
    const sub2Token = await auth(sub2Data.did, sub2Data.privateKey)

    await app.request('/v1/trust/attest', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${attesterToken}` }, body: JSON.stringify({ issuerDid: issuerData.did }) })
    const issueRes = await app.request('/v1/credentials/issue', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${issuerToken}` }, body: JSON.stringify({ subjectDid: sub1Data.did, credentialType: ['Test'], claims: { secret: 'value' } }) })
    const { id: credId } = await issueRes.json()

    // sub2 tries to read sub1's credential
    const res = await app.request(`/v1/credentials/${credId}`, { headers: { Authorization: `Bearer ${sub2Token}` } })
    expect(res.status).toBe(403)
  })
})

describe('API5 — Broken Function Level Authorization', () => {
  test('subject cannot issue a credential', async () => {
    const createRes = await app.request('/v1/dids', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role: 'subject' }) })
    const { did, privateKey } = await createRes.json()
    const chalRes = await app.request('/v1/auth/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ did }) })
    const { challengeId, nonce } = await chalRes.json()
    const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020')
    const kp = await Ed25519VerificationKey2020.from({ type: 'Ed25519VerificationKey2020', privateKeyMultibase: privateKey, publicKeyMultibase: did.replace('did:key:', '') })
    const sig = Buffer.from(await kp.signer().sign({ data: new TextEncoder().encode(`${did}:${nonce}`) })).toString('base64')
    const vr = await app.request('/v1/auth/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ did, challengeId, signature: sig }) })
    const { token } = await vr.json()
    const res = await app.request('/v1/credentials/issue', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ subjectDid: did, credentialType: ['Test'], claims: {} }) })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('UNAUTHORIZED_ROLE')
  })
})

describe('API8 — Security Misconfiguration', () => {
  test('all responses include required security headers', async () => {
    const res = await app.request('/health')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('strict-transport-security')).toBeTruthy()
    expect(res.headers.get('cache-control')).toBe('no-store')
  })
})

describe('API10 — Input Validation', () => {
  test('missing required fields return 400', async () => {
    const res = await app.request('/v1/auth/challenge', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    })
    expect(res.status).toBe(400)
  })

  test('invalid role returns 400', async () => {
    const res = await app.request('/v1/dids', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'hacker' }),
    })
    expect(res.status).toBe(400)
  })
})
```

- [ ] **Step 2: Run**

```bash
bun test tests/security/owasp.test.ts
```

Expected: all tests pass.

- [ ] **Step 3: Run full test suite**

```bash
bun test
```

Expected: unit + integration + security all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/security/owasp.test.ts
git commit -m "test: OWASP API Security Top 10 security tests"
```

---

## Self-Review

**Spec coverage check:**
- ✅ All 18 endpoints implemented (auth×2, did×4, credentials×5, presentations×3, trust×4)
- ✅ Four actor roles: subject, issuer, verifier, attester
- ✅ did:key generation (Ed25519 for DID auth, BLS12-381 for issuers)
- ✅ BBS+ sign / derive / verify (Tasks 7, 13, 14)
- ✅ W3C VC Data Model 2.0 + DataIntegrityProof (bbs-2023) (Task 13)
- ✅ DID Auth challenge/response (Task 10)
- ✅ Private key AES-GCM encryption (Task 5)
- ✅ Offline JSON-LD context loader (Task 8)
- ✅ PostgreSQL with all 7 tables including audit_log (Task 4)
- ✅ OWASP API1–API10 mitigations (Tasks 9, 10, 19)
- ✅ Selective disclosure — only revealed claims returned to verifier (Task 14)
- ✅ Attester as trust registry (Tasks 12, 13)
- ✅ Rate limiting: 10 req/min on sensitive routes, 100 req/min general (Tasks 9, 13)
- ✅ Body size limit 64KB (Task 15)
- ✅ Security headers (Task 9)
- ✅ Audit log (Tasks 4, 13, 14)
- ✅ Zod input validation on all routes
- ✅ `/me` registered before `/:did` in DID router (Task 11)
- ✅ BBS+ derive uses issuer public key; subject private key used only for holder-binding VP (Task 14)
