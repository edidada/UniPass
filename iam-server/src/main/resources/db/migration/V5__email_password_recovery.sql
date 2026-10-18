CREATE TABLE recovery_contact (
 user_id uuid PRIMARY KEY REFERENCES iam_user(id), email varchar(254) NOT NULL,
 contact_version uuid NOT NULL UNIQUE, verified_at timestamptz NOT NULL,
 evidence_ref varchar(500) NOT NULL, enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE reset_mail_request (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), contact_version uuid NOT NULL,
 state varchar(16) NOT NULL CHECK(state IN ('PENDING','RUNNING','SENT','DEAD','BLOCKED')),
 attempts integer NOT NULL DEFAULT 0, lease_token uuid, lease_until timestamptz,
 next_attempt_at timestamptz NOT NULL, last_error varchar(64), created_at timestamptz NOT NULL
);
CREATE INDEX reset_mail_due ON reset_mail_request(next_attempt_at) WHERE state IN ('PENDING','RUNNING');
CREATE TABLE reset_email_challenge (
 token_digest char(64) PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id),
 request_id uuid NOT NULL REFERENCES reset_mail_request(id), auth_epoch bigint NOT NULL,
 contact_version uuid NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz
);
CREATE TABLE reset_browser_grant (
 token_digest char(64) PRIMARY KEY REFERENCES password_reset_grant(token_digest),
 session_digest varchar(71) NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE admin_password_action (
 id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES iam_user(id), target_id uuid NOT NULL REFERENCES iam_user(id),
 action varchar(32) NOT NULL, idempotency_key varchar(128) NOT NULL, reason varchar(500) NOT NULL,
 operation_id uuid REFERENCES password_operation(id), requested_operation_id uuid REFERENCES password_operation(id),
 evidence_ref varchar(500), created_at timestamptz NOT NULL,
 UNIQUE(actor_id,target_id,action,idempotency_key)
);
