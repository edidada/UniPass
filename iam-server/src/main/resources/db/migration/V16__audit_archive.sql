-- V16: audit archive (T8 fourth increment).
-- Rows older than the retention window are moved, not dropped, so the
-- six-month (configurable) minimum can be restored with an integrity check.
CREATE TABLE audit_archive (
 id uuid PRIMARY KEY,
 user_id uuid,
 action varchar(64) NOT NULL,
 trace_id uuid NOT NULL,
 login_id uuid,
 result varchar(24) NOT NULL,
 client_id varchar(100),
 source_ip varchar(64),
 operation_id uuid,
 detail jsonb NOT NULL,
 created_at timestamptz NOT NULL,
 archived_at timestamptz NOT NULL DEFAULT now(),
 batch_id uuid NOT NULL
);
CREATE INDEX audit_archive_time ON audit_archive(created_at);
CREATE INDEX audit_archive_batch_index ON audit_archive(batch_id);
CREATE TABLE audit_archive_batch (
 id uuid PRIMARY KEY,
 cutoff timestamptz NOT NULL,
 rows bigint NOT NULL CHECK (rows > 0),
 digest char(64) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
