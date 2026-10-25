-- V17: application (client) soft delete (T8 fifth increment, N2 part).
-- A deleted application keeps its registration and audit rows but gains an
-- irreversible tombstone so it can never be re-enabled or re-registered without
-- an explicit offline cleanup. Disabled state is preserved for the back-channel
-- and protocol filters that already key off it.
ALTER TABLE oauth_client_status ADD COLUMN deleted_at timestamptz;
ALTER TABLE oauth_client_status ADD COLUMN deleted_by uuid REFERENCES iam_user(id);
ALTER TABLE oauth_client_status ADD COLUMN delete_reason varchar(500);
CREATE INDEX client_status_deleted ON oauth_client_status(deleted_at) WHERE deleted_at IS NOT NULL;
