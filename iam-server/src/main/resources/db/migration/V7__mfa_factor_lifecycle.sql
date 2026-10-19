ALTER TABLE iam_user ADD COLUMN mfa_recovery_required boolean NOT NULL DEFAULT false;
CREATE TABLE mfa_recovery_grant (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), actor_id uuid NOT NULL REFERENCES iam_user(id),
 actor_epoch bigint NOT NULL, auth_epoch bigint NOT NULL, token_digest varchar(72) NOT NULL UNIQUE,
 idempotency_key varchar(128) NOT NULL, reason varchar(500) NOT NULL, evidence_ref varchar(500) NOT NULL,
 expires_at timestamptz NOT NULL, consumed_at timestamptz, revoked_at timestamptz, created_at timestamptz NOT NULL,
 UNIQUE(actor_id,user_id,idempotency_key), CHECK(actor_id<>user_id)
);
CREATE TABLE mfa_factor_change (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), auth_epoch bigint NOT NULL,
 session_digest varchar(72) NOT NULL, secret_cipher bytea, mode varchar(8) NOT NULL CHECK(mode IN ('ROTATE','RECOVER')),
 recovery_grant_id uuid REFERENCES mfa_recovery_grant(id),
 state varchar(16) NOT NULL CHECK(state IN ('PENDING','COMMITTED','SUPERSEDED','CANCELLED','EXPIRED')),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL, finished_at timestamptz,
 CHECK ((mode='RECOVER')=(recovery_grant_id IS NOT NULL)),
 CHECK ((state='PENDING')=(secret_cipher IS NOT NULL))
);
CREATE UNIQUE INDEX mfa_factor_change_pending ON mfa_factor_change(user_id) WHERE state='PENDING';
CREATE TABLE mfa_lifecycle_guard (
 user_id uuid PRIMARY KEY REFERENCES iam_user(id), failed_attempts integer NOT NULL DEFAULT 0,
 locked_until timestamptz
);
