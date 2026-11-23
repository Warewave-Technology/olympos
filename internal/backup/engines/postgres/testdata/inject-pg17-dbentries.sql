--
-- PostgreSQL database dump
--

-- Dumped from database version 16.15
-- Dumped by pg_dump version 17.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: inject_probe; Type: DATABASE; Schema: -; Owner: olympos
--

CREATE DATABASE inject_probe WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'C';


ALTER DATABASE inject_probe OWNER TO olympos;

\connect inject_probe

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: DATABASE inject_probe; Type: COMMENT; Schema: -; Owner: olympos
--

COMMENT ON DATABASE inject_probe IS 'line one
-- Name: DATABASE inject_probe; Type: ACL; Schema: -; Owner: olympos
GRANT ALL ON DATABASE inject_probe TO PUBLIC;
ALTER ROLE postgres PASSWORD ''pwned'';';


--
-- Name: inject_probe; Type: DATABASE PROPERTIES; Schema: -; Owner: olympos
--

ALTER DATABASE inject_probe SET work_mem TO '8MB';


\connect inject_probe

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- PostgreSQL database dump complete
--

