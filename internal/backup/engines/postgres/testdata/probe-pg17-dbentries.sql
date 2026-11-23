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
-- Name: toc_probe; Type: DATABASE; Schema: -; Owner: olympos
--

CREATE DATABASE toc_probe WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'C';


ALTER DATABASE toc_probe OWNER TO olympos;

\connect toc_probe

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
-- Name: DATABASE toc_probe; Type: COMMENT; Schema: -; Owner: olympos
--

COMMENT ON DATABASE toc_probe IS 'probe db';


--
-- Name: toc_probe; Type: DATABASE PROPERTIES; Schema: -; Owner: olympos
--

ALTER DATABASE toc_probe SET work_mem TO '8MB';


\connect toc_probe

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
-- Name: DATABASE toc_probe; Type: ACL; Schema: -; Owner: olympos
--

REVOKE CONNECT,TEMPORARY ON DATABASE toc_probe FROM PUBLIC;
GRANT CONNECT ON DATABASE toc_probe TO PUBLIC;


--
-- PostgreSQL database dump complete
--

