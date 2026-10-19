CREATE TABLE auth_runtime_state (
 singleton boolean PRIMARY KEY CHECK(singleton), redis_generation uuid NOT NULL,
 redis_run_id varchar(100), recovered_at timestamptz
);
INSERT INTO auth_runtime_state(singleton,redis_generation) VALUES (true,gen_random_uuid());
CREATE TABLE auth_runtime_recovery (
 id uuid PRIMARY KEY, generation uuid NOT NULL UNIQUE, previous_generation uuid NOT NULL,
 redis_run_id varchar(100) NOT NULL, affected_accounts bigint NOT NULL,
 revoked_families bigint NOT NULL, recovered_at timestamptz NOT NULL
);
