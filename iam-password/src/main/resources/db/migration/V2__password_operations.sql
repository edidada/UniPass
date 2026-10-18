ALTER TABLE iam_user ADD COLUMN password_changed_at timestamptz;
ALTER TABLE iam_user ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;

CREATE TABLE password_request_guard (
 user_id uuid PRIMARY KEY REFERENCES iam_user(id), requested_at timestamptz NOT NULL
);
CREATE TABLE password_operation (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), idempotency_key varchar(128) NOT NULL,
 state varchar(16) NOT NULL CHECK(state IN ('PREPARED','COMMITTED','REJECTED','UNKNOWN')),
 operation_type varchar(16) NOT NULL CHECK(operation_type IN ('CHANGE','RESET')),
 force_change boolean NOT NULL DEFAULT false,
 fenced_epoch bigint NOT NULL, source_version text,
 lease_until timestamptz NOT NULL, error_code varchar(64),
 created_at timestamptz NOT NULL, finished_at timestamptz,
 recovery_evidence_ref varchar(500), recovered_by uuid,
 UNIQUE(user_id,idempotency_key)
);
CREATE UNIQUE INDEX one_unfinished_password_operation ON password_operation(user_id) WHERE state IN ('PREPARED','UNKNOWN');
CREATE INDEX password_recovery_due ON password_operation(lease_until) WHERE state='PREPARED';

CREATE TABLE password_audit (
 id uuid PRIMARY KEY, operation_id uuid REFERENCES password_operation(id), user_id uuid NOT NULL REFERENCES iam_user(id),
 actor_id uuid NOT NULL, action varchar(64) NOT NULL, error_code varchar(64), trace_id uuid NOT NULL,
 created_at timestamptz NOT NULL
);
CREATE INDEX password_audit_user_time ON password_audit(user_id,created_at);

CREATE TABLE outbox_event (
 event_id uuid PRIMARY KEY, aggregate_id uuid NOT NULL REFERENCES iam_user(id), event_type varchar(100) NOT NULL,
 schema_version integer NOT NULL DEFAULT 1, auth_epoch bigint NOT NULL,
 payload jsonb NOT NULL, created_at timestamptz NOT NULL, published_at timestamptz
);
CREATE INDEX outbox_unpublished ON outbox_event(created_at) WHERE published_at IS NULL;
CREATE TABLE sync_task (
 id uuid PRIMARY KEY, event_id uuid NOT NULL REFERENCES outbox_event(event_id), target varchar(64) NOT NULL,
 state varchar(32) NOT NULL CHECK(state IN ('PENDING','RUNNING','SUCCESS','SUCCESS_DEGRADED','SKIPPED','BLOCKED','DEAD')),
 attempt_count integer NOT NULL DEFAULT 0, next_retry_at timestamptz NOT NULL,
 lease_token uuid, lease_until timestamptz, last_error varchar(64),
 UNIQUE(event_id,target)
);
CREATE INDEX sync_due ON sync_task(next_retry_at) WHERE state IN ('PENDING','RUNNING');

CREATE TABLE identity_verification (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), auth_epoch bigint NOT NULL,
 factor varchar(32) NOT NULL CHECK(factor IN ('SMS_OTP','EMAIL_LINK','FEISHU')),
 verified_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz
);
CREATE TABLE password_reset_grant (
 token_digest char(64) PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id), auth_epoch bigint NOT NULL,
 factor varchar(32) NOT NULL, verified_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz, operation_id uuid REFERENCES password_operation(id)
);
