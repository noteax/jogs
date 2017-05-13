CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE ROLE anonymous;
CREATE ROLE regular_user;
CREATE ROLE user_manager;
CREATE ROLE admin;

CREATE SCHEMA hidden;

DROP TABLE IF EXISTS hidden.users;
CREATE TABLE hidden.users (
  id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  pass TEXT NOT NULL,
  role NAME NOT NULL
);

DROP TYPE hidden.JWT_CLAIMS;
CREATE TYPE hidden.JWT_CLAIMS AS (id UUID, role TEXT, name TEXT);

CREATE OR REPLACE FUNCTION hidden.check_role_exists()
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

CREATE OR REPLACE FUNCTION hidden.hash_pass()
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

CREATE OR REPLACE FUNCTION
  hidden.user_role(a_name TEXT, a_pass TEXT)
  RETURNS NAME
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN (
    SELECT role
    FROM hidden.users
    WHERE users.name = a_name AND
          users.pass = crypt(a_pass, users.pass)
  );
END;
$$;

CREATE OR REPLACE FUNCTION login(name TEXT, pass TEXT)
  RETURNS hidden.JWT_CLAIMS
LANGUAGE PLPGSQL
AS $$
DECLARE
  _role  NAME;
  result hidden.JWT_CLAIMS;
BEGIN
  SELECT hidden.user_role(name, pass)
  INTO _role;

  IF _role IS NULL
  THEN
    RAISE invalid_password
    USING MESSAGE = 'invalid user or password';
  END IF;

  SELECT
    _role      AS role,
    login.name AS name
  INTO result;

  RETURN result;
END;
$$;

DROP FUNCTION signup( TEXT, TEXT, NAME );
CREATE OR REPLACE FUNCTION signup(a_name TEXT, a_pass TEXT, a_role NAME)
  RETURNS VOID
LANGUAGE PLPGSQL
AS $$
BEGIN
  INSERT INTO hidden.users (name, pass, role)
  VALUES (a_name, a_pass, a_role);
END;
$$;
