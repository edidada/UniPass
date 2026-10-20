CREATE TABLE oidc_rp_session (
 authorization_id varchar(100) PRIMARY KEY REFERENCES oauth2_authorization(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES iam_user(id), client_id varchar(100) NOT NULL,
 target_uri varchar(1000) NOT NULL, sid varchar(200) NOT NULL, login_authenticated_at timestamptz NOT NULL
);
CREATE TABLE oidc_logout_task (
 id uuid PRIMARY KEY, authorization_id varchar(100) NOT NULL UNIQUE,
 user_id uuid NOT NULL REFERENCES iam_user(id), client_id varchar(100) NOT NULL,
 target_uri varchar(1000) NOT NULL, sid varchar(200) NOT NULL, login_authenticated_at timestamptz NOT NULL,
 state varchar(16) NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','RUNNING','SENT','DEAD')),
 attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
 lease_token uuid, lease_until timestamptz, finished_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oidc_logout_pending ON oidc_logout_task(next_attempt_at) WHERE state IN ('PENDING','RUNNING');
CREATE INDEX oidc_logout_login ON oidc_logout_task(user_id,client_id,login_authenticated_at);
CREATE FUNCTION enqueue_oidc_logout() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revoked AND NOT OLD.revoked THEN
  INSERT INTO oidc_logout_task(id,authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at)
   SELECT gen_random_uuid(),authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at
   FROM oidc_rp_session WHERE authorization_id=NEW.id
   ON CONFLICT(authorization_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER authorization_backchannel AFTER UPDATE OF revoked ON oauth2_authorization
 FOR EACH ROW EXECUTE FUNCTION enqueue_oidc_logout();
CREATE FUNCTION revoke_changed_identity_authorizations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.auth_epoch<>OLD.auth_epoch OR NEW.status<>OLD.status OR (OLD.password_gate='OPEN' AND NEW.password_gate='BLOCKED') THEN
  UPDATE oauth2_authorization SET revoked=true WHERE principal_name=NEW.id::text AND revoked=false;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER identity_backchannel AFTER UPDATE OF auth_epoch,status,password_gate ON iam_user
 FOR EACH ROW EXECUTE FUNCTION revoke_changed_identity_authorizations();
-- Old deployments have no RP-session mapping. Require fresh logins rather than imply
-- their existing browser sessions were enrolled for back-channel delivery.
UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE status='ACTIVE' AND password_gate='OPEN';
UPDATE oauth2_authorization SET revoked=true WHERE revoked=false;
