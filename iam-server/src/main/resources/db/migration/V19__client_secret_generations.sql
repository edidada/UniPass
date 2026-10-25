-- V19: multiple previous client-secret generations (T8 seventh increment, N2 part).
-- The earlier schema kept exactly one previous verifier per client. Rotation now
-- appends the retired verifier instead of overwriting the only row, so successive
-- rotations keep each generation until its own original deadline. A later
-- rotation never extends or restores an older generation; expired rows are
-- deleted by the next rotation. No cleartext or hash is moved between clients.
ALTER TABLE oauth_client_secret_previous DROP CONSTRAINT oauth_client_secret_previous_pkey;
ALTER TABLE oauth_client_secret_previous ADD COLUMN id uuid;
UPDATE oauth_client_secret_previous SET id=gen_random_uuid() WHERE id IS NULL;
ALTER TABLE oauth_client_secret_previous ALTER COLUMN id SET NOT NULL;
ALTER TABLE oauth_client_secret_previous ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE oauth_client_secret_previous ADD CONSTRAINT oauth_client_secret_previous_pkey PRIMARY KEY (id);
CREATE INDEX client_secret_previous_active ON oauth_client_secret_previous(client_id, valid_until);
