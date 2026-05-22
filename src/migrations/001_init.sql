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
