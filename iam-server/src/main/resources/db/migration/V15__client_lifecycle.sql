-- V15: application lifecycle (T8 third increment).
-- Disabled clients are blocked at every protocol endpoint by a filter and their
-- existing authorizations are revoked, which reuses the V8 back-channel queue.
CREATE TABLE oauth_client_status (
 client_id varchar(100) PRIMARY KEY REFERENCES oauth2_registered_client(client_id) ON DELETE CASCADE,
 disabled boolean NOT NULL DEFAULT false,
 reason varchar(500),
 updated_at timestamptz NOT NULL DEFAULT now()
);
