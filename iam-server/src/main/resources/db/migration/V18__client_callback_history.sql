-- V18: callback configuration history (T8 sixth increment, N2 part).
-- Every register and every callback-changing update snapshots the exact
-- redirect/logout/back-channel configuration with actor and reason. Rows are
-- append-only; no secret material is stored. History for soft-deleted clients
-- is retained for audit but the management API answers 404 (deleted clients are
-- hidden from the live management surface).
CREATE TABLE oauth_client_callback_history (
 id uuid PRIMARY KEY,
 seq bigserial NOT NULL,
 client_id varchar(100) NOT NULL REFERENCES oauth2_registered_client(client_id) ON DELETE CASCADE,
 action varchar(16) NOT NULL CHECK (action IN ('REGISTER','UPDATE')),
 redirect_uris jsonb NOT NULL,
 post_logout_redirect_uris jsonb NOT NULL,
 backchannel_logout_uri varchar(1000),
 actor_id uuid NOT NULL REFERENCES iam_user(id),
 reason varchar(500) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX client_callback_history_time ON oauth_client_callback_history(client_id, created_at DESC);
