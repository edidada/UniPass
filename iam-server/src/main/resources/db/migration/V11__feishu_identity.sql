CREATE TABLE feishu_connector (
 singleton boolean PRIMARY KEY CHECK(singleton), app_id varchar(128) NOT NULL,
 tenant_key varchar(128) NOT NULL, enabled boolean NOT NULL DEFAULT false,
 UNIQUE(app_id,tenant_key)
);
CREATE TABLE feishu_capability (
 capability varchar(32) PRIMARY KEY CHECK(capability IN ('LOGIN','CONTACT_READ','SESSION_REVOKE','PASSWORD_WRITE')),
 state varchar(16) NOT NULL CHECK(state IN ('UNVERIFIED','VERIFIED','UNAVAILABLE')),
 permissions varchar(1000) NOT NULL DEFAULT '', official_url varchar(500) NOT NULL,
 verified_at timestamptz, valid_until timestamptz, evidence_ref varchar(500),
 CHECK(state<>'VERIFIED' OR (verified_at IS NOT NULL AND valid_until IS NOT NULL AND evidence_ref IS NOT NULL
 AND valid_until>verified_at AND valid_until<=verified_at+interval '7 days' AND length(trim(evidence_ref))>0))
);
INSERT INTO feishu_capability(capability,state,official_url) VALUES
 ('LOGIN','UNVERIFIED','https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/authentication-management/access-token/get-user-access-token-v3'),
 ('CONTACT_READ','UNVERIFIED','https://open.feishu.cn/document/server-docs/contact-v3/user/list'),
 ('SESSION_REVOKE','UNAVAILABLE','https://open.feishu.cn/document/'),
 ('PASSWORD_WRITE','UNAVAILABLE','https://open.feishu.cn/document/');
CREATE TABLE feishu_binding (
 tenant_key varchar(128) NOT NULL, open_id varchar(128) NOT NULL,
 user_id uuid NOT NULL UNIQUE REFERENCES iam_user(id), bound_epoch bigint NOT NULL,
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_key,open_id)
);
CREATE TABLE feishu_flow (
 state_digest char(71) PRIMARY KEY, session_digest char(71) NOT NULL, ip_digest char(71) NOT NULL,
 mode varchar(8) NOT NULL CHECK(mode IN ('LOGIN','BIND')), actor_id uuid REFERENCES iam_user(id), actor_epoch bigint,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 CHECK((mode='LOGIN' AND actor_id IS NULL AND actor_epoch IS NULL) OR (mode='BIND' AND actor_id IS NOT NULL AND actor_epoch IS NOT NULL))
);
CREATE INDEX feishu_flow_rate ON feishu_flow(ip_digest,created_at);
CREATE INDEX feishu_flow_browser_rate ON feishu_flow(session_digest,created_at);
CREATE TABLE feishu_code_use (code_digest char(71) PRIMARY KEY, consumed_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE feishu_audit (
 id uuid PRIMARY KEY, user_id uuid REFERENCES iam_user(id), action varchar(64) NOT NULL,
 operator_ref varchar(200), evidence_ref varchar(500), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Permission/configuration changes invalidate prior bindings and existing IAM grants.
CREATE FUNCTION protect_feishu_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.app_id<>OLD.app_id OR NEW.tenant_key<>OLD.tenant_key THEN
  RAISE EXCEPTION 'Connector identity is immutable; use a separate deployment for another app/tenant';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER feishu_connector_identity BEFORE UPDATE OR DELETE ON feishu_connector
 FOR EACH ROW EXECUTE FUNCTION protect_feishu_identity();
CREATE FUNCTION fence_feishu_configuration() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id IN (SELECT user_id FROM feishu_binding);
 RETURN NEW;
END $$;
CREATE TRIGGER feishu_connector_fence AFTER UPDATE OR DELETE ON feishu_connector
 FOR EACH ROW EXECUTE FUNCTION fence_feishu_configuration();
CREATE TRIGGER feishu_capability_fence AFTER UPDATE OR DELETE ON feishu_capability
 FOR EACH ROW WHEN(OLD.capability='LOGIN') EXECUTE FUNCTION fence_feishu_configuration();
