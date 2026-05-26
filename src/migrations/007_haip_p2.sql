-- src/migrations/007_haip_p2.sql
CREATE TABLE IF NOT EXISTS oauth_par_requests (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_uri  TEXT NOT NULL UNIQUE,
  client_id    TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code          TEXT NOT NULL UNIQUE,
  client_id     TEXT NOT NULL,
  redirect_uri  TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope         TEXT NOT NULL,
  did           TEXT NOT NULL,
  used          BOOLEAN NOT NULL DEFAULT false,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_dpop_nonces (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce      TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
