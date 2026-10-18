CREATE TABLE mfa_totp (
 user_id uuid PRIMARY KEY REFERENCES iam_user(id),
 secret_cipher bytea NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 pending_expires_at timestamptz,
 last_used_step bigint NOT NULL DEFAULT -1,
 failed_attempts integer NOT NULL DEFAULT 0,
 locked_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE mfa_challenge (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), auth_epoch bigint NOT NULL,
 session_digest varchar(72) NOT NULL, context_id uuid NOT NULL,
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mfa_challenge_user ON mfa_challenge(user_id,created_at);
