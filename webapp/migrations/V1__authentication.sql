CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE ROLE authenticator NOINHERIT;
CREATE ROLE anon;
CREATE ROLE regular;
CREATE ROLE manager;
CREATE ROLE admin;

GRANT anon TO authenticator;
GRANT regular TO authenticator;
GRANT manager TO authenticator;
GRANT admin TO authenticator;

CREATE SCHEMA hidden;

DROP TABLE IF EXISTS hidden.users;
CREATE TABLE hidden.users (
  id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  pass TEXT NOT NULL,
  role NAME NOT NULL
);

DROP TYPE JWT_CLAIMS;
CREATE TYPE JWT_CLAIMS AS (
  id   UUID,
  name TEXT,
  role NAME
);

CREATE FUNCTION current_user_id()
  RETURNS UUID
STABLE
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN current_setting('request.jwt.claim.id');
END;
$$;

CREATE FUNCTION hidden.check_role_exists()
  RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
BEGIN
  IF NOT exists(SELECT 1
                FROM pg_roles AS r
                WHERE r.rolname = new.role)
  THEN
    RAISE foreign_key_violation
    USING MESSAGE = 'unknown database role: ' || new.role;
    RETURN NULL;
  END IF;
  RETURN new;
END;
$$;

CREATE TRIGGER ensure_user_role_exists
AFTER INSERT OR UPDATE ON hidden.users
FOR EACH ROW
EXECUTE PROCEDURE hidden.check_role_exists();

CREATE FUNCTION hidden.hash_pass()
  RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
BEGIN
  IF tg_op = 'INSERT' OR new.pass <> old.pass
  THEN
    new.pass = crypt(new.pass, gen_salt('bf'));
  END IF;
  RETURN new;
END;
$$;

CREATE TRIGGER hash_pass
BEFORE INSERT OR UPDATE ON hidden.users
FOR EACH ROW
EXECUTE PROCEDURE hidden.hash_pass();

CREATE FUNCTION hidden.get_token(_name TEXT, _pass TEXT)
  RETURNS JWT_CLAIMS
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (
    SELECT
      id,
      name,
      role
    FROM hidden.users
    WHERE name = _name AND
          pass = crypt(_pass, pass)
  );
END;
$$;

CREATE FUNCTION register(_name TEXT, _pass TEXT, _role NAME)
  RETURNS JWT_CLAIMS
LANGUAGE plpgsql
AS $$
DECLARE result JWT_CLAIMS;
BEGIN
  INSERT INTO hidden.users (name, pass, role) VALUES (_name, _pass, _role)
  RETURNING id, name, role
    INTO result;
  RETURN result;
END;
$$;

CREATE FUNCTION login(_name TEXT, _pass TEXT)
  RETURNS JWT_CLAIMS
LANGUAGE PLPGSQL
AS $$
DECLARE
  result JWT_CLAIMS;
BEGIN
  SELECT hidden.get_token(_name, _pass)
  INTO result;

  IF result IS NULL
  THEN
    RAISE invalid_password
    USING MESSAGE = 'invalid user or password';
  END IF;

  RETURN result;
END;
$$;
