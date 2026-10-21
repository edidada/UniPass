ALTER TABLE sync_task ADD COLUMN lease_owner uuid;
ALTER TABLE sync_task ADD COLUMN lease_version bigint NOT NULL DEFAULT 0;
ALTER TABLE sync_task ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sync_task ADD COLUMN finished_at timestamptz;
-- No previous release consumes these tasks. Recover any legacy incomplete claim.
UPDATE sync_task SET state='PENDING' WHERE state='RUNNING';
UPDATE sync_task SET lease_token=NULL,lease_until=NULL;
ALTER TABLE sync_task ADD CONSTRAINT sync_attempts_nonnegative CHECK(attempt_count>=0 AND lease_version>=0);
ALTER TABLE sync_task ADD CONSTRAINT sync_lease_shape CHECK(
 (state='RUNNING' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
 OR (state<>'RUNNING' AND lease_owner IS NULL AND lease_token IS NULL AND lease_until IS NULL));
CREATE INDEX sync_expired_lease ON sync_task(lease_until) WHERE state='RUNNING';

CREATE TABLE sync_task_audit (
 id uuid PRIMARY KEY, task_id uuid NOT NULL REFERENCES sync_task(id),
 action varchar(24) NOT NULL CHECK(action IN ('CLAIMED','FINISHED','EXHAUSTED','REQUEUED')),
 state varchar(32) NOT NULL, attempt_count integer NOT NULL, lease_version bigint NOT NULL,
 previous_attempt_count integer,
 result_code varchar(64), operator_ref varchar(200) NOT NULL, evidence_ref varchar(500),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX sync_audit_task ON sync_task_audit(task_id,created_at);

-- published_at means durable task fan-out, never successful external delivery.
CREATE FUNCTION fanout_sync_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.event_type IN ('unipass.password.changed','unipass.user.disabled') THEN
  INSERT INTO sync_task(id,event_id,target,state,next_retry_at)
   SELECT gen_random_uuid(),NEW.event_id,target,'PENDING',clock_timestamp()
   FROM (VALUES ('FEISHU_APP_REAUTH'),('APP_PUSH')) AS targets(target)
   ON CONFLICT(event_id,target) DO NOTHING;
  UPDATE outbox_event SET published_at=clock_timestamp() WHERE event_id=NEW.event_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sync_event_fanout AFTER INSERT ON outbox_event
 FOR EACH ROW EXECUTE FUNCTION fanout_sync_event();

CREATE FUNCTION enqueue_disabled_sync_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='DISABLED' AND OLD.status<>'DISABLED' THEN
  INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at)
   VALUES(gen_random_uuid(),NEW.id,'unipass.user.disabled',NEW.auth_epoch,
    jsonb_build_object('user_id',NEW.id,'auth_epoch',NEW.auth_epoch),clock_timestamp());
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_sync_disabled AFTER UPDATE OF status ON iam_user
 FOR EACH ROW EXECUTE FUNCTION enqueue_disabled_sync_event();

-- Preserve old task identity/results and supply only missing fan-out targets.
INSERT INTO sync_task(id,event_id,target,state,next_retry_at)
 SELECT gen_random_uuid(),e.event_id,t.target,'PENDING',clock_timestamp()
 FROM outbox_event e CROSS JOIN (VALUES ('FEISHU_APP_REAUTH'),('APP_PUSH')) AS t(target)
 WHERE e.event_type IN ('unipass.password.changed','unipass.user.disabled')
 ON CONFLICT(event_id,target) DO NOTHING;
UPDATE outbox_event SET published_at=clock_timestamp()
 WHERE published_at IS NULL AND event_type IN ('unipass.password.changed','unipass.user.disabled');
-- Accounts already disabled before V10 also need downstream reconciliation.
INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at)
 SELECT gen_random_uuid(),u.id,'unipass.user.disabled',u.auth_epoch,
  jsonb_build_object('user_id',u.id,'auth_epoch',u.auth_epoch),clock_timestamp()
 FROM iam_user u WHERE u.status='DISABLED' AND NOT EXISTS (
  SELECT 1 FROM outbox_event e WHERE e.aggregate_id=u.id
   AND e.event_type='unipass.user.disabled' AND e.auth_epoch=u.auth_epoch);
