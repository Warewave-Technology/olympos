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
-- Name: s; Type: SCHEMA; Schema: -; Owner: olympos
--

CREATE SCHEMA s;


ALTER SCHEMA s OWNER TO olympos;

--
-- Name: f(); Type: FUNCTION; Schema: s; Owner: olympos
--

CREATE FUNCTION s.f() RETURNS integer
    LANGUAGE sql
    AS $$select 1$$;


ALTER FUNCTION s.f() OWNER TO olympos;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: Odd Name; Type: TABLE; Schema: public; Owner: olympos
--

CREATE TABLE public."Odd Name" (
    x integer
);


ALTER TABLE public."Odd Name" OWNER TO olympos;

--
-- Name: mv; Type: MATERIALIZED VIEW; Schema: s; Owner: olympos
--

CREATE MATERIALIZED VIEW s.mv AS
 SELECT 1 AS a
  WITH NO DATA;


ALTER MATERIALIZED VIEW s.mv OWNER TO olympos;

--
-- Name: p; Type: TABLE; Schema: s; Owner: olympos
--

CREATE TABLE s.p (
    id integer
)
PARTITION BY RANGE (id);


ALTER TABLE s.p OWNER TO olympos;

--
-- Name: p1; Type: TABLE; Schema: s; Owner: olympos
--

CREATE TABLE s.p1 (
    id integer
);


ALTER TABLE s.p1 OWNER TO olympos;

--
-- Name: q; Type: SEQUENCE; Schema: s; Owner: olympos
--

CREATE SEQUENCE s.q
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE s.q OWNER TO olympos;

--
-- Name: t; Type: TABLE; Schema: s; Owner: olympos
--

CREATE TABLE s.t (
    id integer NOT NULL,
    v text
);


ALTER TABLE s.t OWNER TO olympos;

--
-- Name: v; Type: VIEW; Schema: s; Owner: olympos
--

CREATE VIEW s.v AS
 SELECT 1 AS "?column?";


ALTER VIEW s.v OWNER TO olympos;

--
-- Name: p1; Type: TABLE ATTACH; Schema: s; Owner: olympos
--

ALTER TABLE ONLY s.p ATTACH PARTITION s.p1 FOR VALUES FROM (0) TO (10);


--
-- Name: t t_pkey; Type: CONSTRAINT; Schema: s; Owner: olympos
--

ALTER TABLE ONLY s.t
    ADD CONSTRAINT t_pkey PRIMARY KEY (id);


--
-- Name: DATABASE toc_probe; Type: ACL; Schema: -; Owner: olympos
--

REVOKE CONNECT,TEMPORARY ON DATABASE toc_probe FROM PUBLIC;
GRANT CONNECT ON DATABASE toc_probe TO PUBLIC;


--
-- Name: mv; Type: MATERIALIZED VIEW DATA; Schema: s; Owner: olympos
--

REFRESH MATERIALIZED VIEW s.mv;


--
-- PostgreSQL database dump complete
--

