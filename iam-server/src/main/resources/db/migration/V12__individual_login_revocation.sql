CREATE TABLE iam_login (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES iam_user(id) ON DELETE CASCADE,
 auth_epoch bigint NOT NULL, authenticated_at timestamptz NOT NULL,
 last_access_at timestamptz NOT NULL DEFAULT now(),
 authentication_method varchar(16) NOT NULL CHECK(authentication_method IN ('PASSWORD','FEISHU')),
 device varchar(80) NOT NULL DEFAULT 'Unknown', revoked_at timestamptz
);
CREATE INDEX iam_login_owner ON iam_login(user_id,authenticated_at DESC);
CREATE TABLE iam_login_grant (
 authorization_id varchar(100) PRIMARY KEY REFERENCES oauth2_authorization(id) ON DELETE CASCADE,
 login_id uuid NOT NULL REFERENCES iam_login(id) ON DELETE CASCADE
);
CREATE INDEX iam_login_grant_login ON iam_login_grant(login_id);
ALTER TABLE auth_audit ADD COLUMN login_id uuid;
-- Existing principals and tokens have no stable login ID. Fence before enabling
-- individual revocation; do not disturb a pending password operation's epoch.
UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE status='ACTIVE' AND password_gate='OPEN';
UPDATE oauth2_authorization SET revoked=true WHERE revoked=false;
