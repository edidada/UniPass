-- V20: per-client secret rotation window (T8 eighth increment, N2 part).
-- NULL means the global unipass.clients.secret-rotation-window applies. A value
-- is bounded to 1 minute .. 7 days. The window only changes how long the
-- retiring verifier stays valid; it never weakens the multi-generation or
-- disabled-wins checks.
ALTER TABLE oauth_client_status ADD COLUMN secret_rotation_window_seconds integer;
ALTER TABLE oauth_client_status ADD CONSTRAINT client_rotation_window_range
 CHECK (secret_rotation_window_seconds IS NULL OR
        secret_rotation_window_seconds BETWEEN 60 AND 604800);
