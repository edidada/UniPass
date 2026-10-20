CREATE TABLE mfa_encryption_key (
 key_id varchar(48) PRIMARY KEY CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$'),
 fingerprint char(64) NOT NULL UNIQUE, state varchar(16) NOT NULL CHECK(state IN ('AVAILABLE','RETIRED')),
 introduced_at timestamptz NOT NULL DEFAULT now(), retired_at timestamptz
);
CREATE TABLE mfa_encryption_control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 active_key varchar(48) REFERENCES mfa_encryption_key(key_id)
);
INSERT INTO mfa_encryption_control(singleton) VALUES (true);
CREATE TABLE mfa_key_audit (
 id uuid PRIMARY KEY, action varchar(32) NOT NULL, source_key varchar(48), target_key varchar(48),
 operator_ref varchar(200) NOT NULL, evidence_ref varchar(500) NOT NULL, changed_rows integer NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION mfa_envelope_key(value bytea) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE size integer; name text;
BEGIN
 IF octet_length(value)<29 THEN RAISE EXCEPTION 'Invalid factor envelope'; END IF;
 IF get_byte(value,0)=1 THEN RETURN 'legacy'; END IF;
 IF get_byte(value,0)<>2 THEN RAISE EXCEPTION 'Invalid factor envelope'; END IF;
 size:=get_byte(value,1);
 IF size<1 OR size>48 OR octet_length(value)<2+size+28 THEN RAISE EXCEPTION 'Invalid factor envelope'; END IF;
 name:=convert_from(substring(value FROM 3 FOR size),'UTF8');
 IF name='legacy' OR name !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$' THEN RAISE EXCEPTION 'Invalid factor envelope'; END IF;
 RETURN name;
END $$;
CREATE FUNCTION require_current_mfa_writer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE writer text;
BEGIN
 IF NEW.secret_cipher IS NULL THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND NEW.secret_cipher IS NOT DISTINCT FROM OLD.secret_cipher THEN RETURN NEW; END IF;
 SELECT active_key INTO writer FROM mfa_encryption_control WHERE singleton FOR SHARE;
 IF writer IS NULL OR writer<>mfa_envelope_key(NEW.secret_cipher) THEN RAISE EXCEPTION 'Factor encryption writer changed'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER totp_key_writer BEFORE INSERT OR UPDATE OF secret_cipher ON mfa_totp
 FOR EACH ROW EXECUTE FUNCTION require_current_mfa_writer();
CREATE TRIGGER pending_factor_key_writer BEFORE INSERT OR UPDATE OF secret_cipher ON mfa_factor_change
 FOR EACH ROW EXECUTE FUNCTION require_current_mfa_writer();
