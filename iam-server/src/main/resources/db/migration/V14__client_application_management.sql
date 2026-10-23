-- V14: T8 application/client management and independent management authorities.
-- oauth2_registered_client gains a durable enable/disable state plus the dual
-- client-secret rotation window. Only the verifiable hashes live here; the
-- clear secret is never stored.
ALTER TABLE oauth2_registered_client ADD COLUMN enabled boolean NOT NULL DEFAULT true;
ALTER TABLE oauth2_registered_client ADD COLUMN secret_key_id varchar(32);
ALTER TABLE oauth2_registered_client ADD COLUMN secret_previous varchar(200);
ALTER TABLE oauth2_registered_client ADD COLUMN secret_previous_key_id varchar(32);
ALTER TABLE oauth2_registered_client ADD COLUMN secret_previous_until timestamptz;
-- Backfill: every client provisioned before this migration (CLI or test seeds)
-- keeps working unchanged; enabled defaults to true so no registration is
-- silently disabled by the upgrade.
CREATE INDEX authorization_client_active ON oauth2_authorization(registered_client_id) WHERE revoked=false;
-- Idempotent client actions follow the admin_console_action pattern: the same
-- actor+client+action+normalized-request digest and key must replay to the same
-- outcome, and context changes are rejected instead of silently re-applied.
CREATE TABLE iam_client_action (
 id uuid PRIMARY KEY,
 actor_id uuid NOT NULL REFERENCES iam_user(id),
 registered_client_id varchar(100) NOT NULL,
 action varchar(32) NOT NULL,
 request_digest varchar(64) NOT NULL,
 idempotency_key varchar(128) NOT NULL,
 reason varchar(500) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id, registered_client_id, action, request_digest, idempotency_key)
);
CREATE INDEX iam_client_action_client ON iam_client_action(registered_client_id);
