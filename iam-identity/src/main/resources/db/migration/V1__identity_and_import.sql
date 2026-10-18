CREATE TABLE import_source (
 source_id varchar(100) PRIMARY KEY, cursor_value varchar(500) NOT NULL
);
CREATE TABLE iam_user (
 id uuid PRIMARY KEY, employee_no varchar(100) NOT NULL UNIQUE,
 directory_id uuid NOT NULL UNIQUE, directory_type varchar(16) NOT NULL CHECK(directory_type IN ('AD','OPENLDAP')),
 ldap_dn text NOT NULL, display_name varchar(200) NOT NULL,
 status varchar(16) NOT NULL CHECK(status IN ('ACTIVE','DISABLED')),
 source_id varchar(100) NOT NULL REFERENCES import_source(source_id), source_version bigint NOT NULL CHECK(source_version >= 0),
 directory_etl_at timestamptz NOT NULL DEFAULT now(), auth_epoch bigint NOT NULL DEFAULT 0 CHECK(auth_epoch >= 0),
 password_gate varchar(16) NOT NULL DEFAULT 'OPEN' CHECK(password_gate IN ('OPEN','BLOCKED'))
);
CREATE TABLE import_batch (
 id uuid PRIMARY KEY, source_id varchar(100) NOT NULL REFERENCES import_source(source_id),
 expected_cursor varchar(500) NOT NULL, next_cursor varchar(500) NOT NULL,
 checksum char(64) NOT NULL, directory_type varchar(16) NOT NULL CHECK(directory_type IN ('AD','OPENLDAP')),
 status varchar(16) NOT NULL CHECK(status IN ('PREVIEW','APPLIED')),
 created_at timestamptz NOT NULL DEFAULT now(), applied_at timestamptz,
 UNIQUE(source_id,checksum)
);
CREATE TABLE import_row (
 batch_id uuid NOT NULL REFERENCES import_batch(id), row_no integer NOT NULL,
 employee_no text, directory_id uuid, ldap_dn text, display_name text, desired_status text,
 source_version bigint, observed_version bigint, error_code varchar(64),
 planned_action varchar(16) NOT NULL CHECK(planned_action IN ('CREATE','UPDATE','DISABLE','REJECTED')),
 PRIMARY KEY(batch_id,row_no)
);
CREATE TABLE directory_disable_task (
 user_id uuid PRIMARY KEY REFERENCES iam_user(id), state varchar(16) NOT NULL CHECK(state IN ('PENDING','DONE')),
 attempts integer NOT NULL DEFAULT 0, lease_token uuid, last_error varchar(64), next_attempt_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX disable_due_idx ON directory_disable_task(next_attempt_at) WHERE state='PENDING';
CREATE TABLE identity_audit (
 id uuid PRIMARY KEY, user_id uuid REFERENCES iam_user(id), batch_id uuid REFERENCES import_batch(id),
 action varchar(64) NOT NULL, trace_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
