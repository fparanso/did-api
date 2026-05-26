-- src/migrations/006_haip_p1.sql
ALTER TABLE dids DROP COLUMN IF EXISTS bls_public_key;
ALTER TABLE dids DROP COLUMN IF EXISTS bls_private_key;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS sd_jwt TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mdoc TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mdoc_doc_type TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS device_key JSONB;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS status_list_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS status_list_index INT;
CREATE SEQUENCE IF NOT EXISTS credential_status_idx_seq;
