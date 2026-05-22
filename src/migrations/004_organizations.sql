-- src/migrations/004_organizations.sql
CREATE TABLE IF NOT EXISTS organizations (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,
  did         TEXT NOT NULL REFERENCES dids(id),
  owner_id    UUID NOT NULL REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_members (
  org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  joined_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS org_invites (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  invited_by   UUID NOT NULL REFERENCES users(id),
  email        TEXT,
  did          TEXT,
  role         TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  token        TEXT NOT NULL UNIQUE,
  accepted     BOOLEAN NOT NULL DEFAULT false,
  expires_at   TIMESTAMPTZ NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (email IS NOT NULL OR did IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS org_members_user_idx  ON org_members (user_id);
CREATE INDEX IF NOT EXISTS org_invites_email_idx ON org_invites (email);
CREATE INDEX IF NOT EXISTS org_invites_did_idx   ON org_invites (did);
CREATE INDEX IF NOT EXISTS org_invites_token_idx ON org_invites (token);
