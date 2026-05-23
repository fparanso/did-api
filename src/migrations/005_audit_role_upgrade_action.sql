-- src/migrations/005_audit_role_upgrade_action.sql
-- Extend audit_log action constraint to include 'role_upgrade'
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check
  CHECK (action IN ('issue', 'revoke', 'verify', 'attest', 'auth', 'role_upgrade'));
