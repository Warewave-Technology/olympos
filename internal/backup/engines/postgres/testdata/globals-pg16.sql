--
-- PostgreSQL database cluster dump
--

\restrict WQf94k0DCQxefnhNjASBfmaS4z7siGvR6fTPcqyPETd2zDbwaoq7O6iRNBlse8n

SET default_transaction_read_only = off;

SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE "Mixed Case";
ALTER ROLE "Mixed Case" WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 5 PASSWORD 'SCRAM-SHA-256$4096:QOejMrCkXqgZYn70QUsjDA==$zzrfcfE+mhUEfCVjqDLCBFuF4u0n80IGwk3aJ3z/588=:qbSPse0/odHImwgrpUWBKvaqypGKAeW2VNevYTLGUfs=';
CREATE ROLE app_owner;
ALTER ROLE app_owner WITH NOSUPERUSER INHERIT NOCREATEROLE CREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:neYgpHgQfuVID62Eg0iEtQ==$IBVwY8HZB4sGfW1+wI2bxfREYPgK2Qphe8nMfW7VD10=:/8hbwsTCMsfKsQZ8bWH4EIOSLKHyCrfrDQL1Pcurc0U=';
CREATE ROLE postgres;
ALTER ROLE postgres WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:FqAAIXcwJZK/ruUSVaA5dQ==$cDBSsEbTJN29ie3qrfngGB1xB/FN6Iz90k8X7zKYaA8=:SQuQd8KqcAZ3lbxk/f8wFi8eah11nT5M6NoD8iIrDAQ=';
CREATE ROLE readers;
ALTER ROLE readers WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
COMMENT ON ROLE readers IS 'read-only; for "reports"';
CREATE ROLE reporting;
ALTER ROLE reporting WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:6ld4M6hfj1pexnSq3nl5hw==$A44+0qRQXGnftrINSRpnE526cILZjBENzCbBtXjNl9g=:GzU6Qpv0aZ1BKHD0gwkR90/H+9p6ehUXUfdtensz4xY=' VALID UNTIL '2030-01-01 00:00:00+00';

--
-- User Configurations
--

--
-- User Config "postgres"
--

ALTER ROLE postgres SET statement_timeout TO '0';

--
-- User Config "reporting"
--

ALTER ROLE reporting SET search_path TO 'reporting', 'public';


--
-- Role memberships
--

GRANT app_owner TO postgres WITH INHERIT TRUE GRANTED BY postgres;
GRANT readers TO "Mixed Case" WITH ADMIN OPTION, INHERIT TRUE GRANTED BY postgres;
GRANT readers TO reporting WITH INHERIT TRUE GRANTED BY postgres;




--
-- Tablespaces
--

CREATE TABLESPACE archive OWNER app_owner LOCATION '/tmp/ts_archive';


\unrestrict WQf94k0DCQxefnhNjASBfmaS4z7siGvR6fTPcqyPETd2zDbwaoq7O6iRNBlse8n

--
-- PostgreSQL database cluster dump complete
--

