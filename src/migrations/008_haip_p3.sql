-- src/migrations/008_haip_p3.sql
CREATE TABLE IF NOT EXISTS vp_sessions (
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
