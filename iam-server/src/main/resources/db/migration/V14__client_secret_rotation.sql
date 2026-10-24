-- V14: application (client) management baseline (T8 second increment).
-- One previous client secret may stay valid for a bounded overlap window while
-- the new secret is rolled out; the current secret lives in the standard
-- oauth2_registered_client row, so a failed rotation cannot lock a client out.
CREATE TABLE oauth_client_secret_previous (
 client_id varchar(100) PRIMARY KEY REFERENCES oauth2_registered_client(client_id) ON DELETE CASCADE,
 secret_hash varchar(200) NOT NULL,
 valid_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE admin_client_action (
 id uuid PRIMARY KEY,
 actor_id uuid NOT NULL REFERENCES iam_user(id),
 client_id varchar(100) NOT NULL,
 action varchar(32) NOT NULL,
 idempotency_key varchar(128) NOT NULL,
 reason varchar(500) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id, client_id, action, idempotency_key)
);
CREATE INDEX admin_client_action_time ON admin_client_action(created_at);
