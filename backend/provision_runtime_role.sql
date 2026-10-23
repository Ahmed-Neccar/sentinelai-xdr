-- Runs as the database bootstrap/migration role, never as the application.
SELECT format(
    'CREATE ROLE sentinel_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'migrator_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_migrator')
\gexec

SELECT format(
    'ALTER ROLE sentinel_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'migrator_password'
)
\gexec

SELECT format(
    'CREATE ROLE sentinel_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_runtime')
\gexec

SELECT format(
    'ALTER ROLE sentinel_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'app_password'
)
\gexec

SELECT format('ALTER DATABASE %I OWNER TO sentinel_migrator', current_database())
\gexec
SELECT format('GRANT CONNECT, CREATE ON DATABASE %I TO sentinel_migrator', current_database())
\gexec
ALTER SCHEMA public OWNER TO sentinel_migrator;
GRANT USAGE, CREATE ON SCHEMA public TO sentinel_migrator;

DO $$
DECLARE
    object_name text;
BEGIN
    FOR object_name IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        EXECUTE format('ALTER TABLE public.%I OWNER TO sentinel_migrator', object_name);
    END LOOP;
    FOR object_name IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' LOOP
        EXECUTE format('ALTER SEQUENCE public.%I OWNER TO sentinel_migrator', object_name);
    END LOOP;
END
$$;

SELECT format('GRANT CONNECT ON DATABASE %I TO sentinel_runtime', current_database())
\gexec
GRANT USAGE ON SCHEMA public TO sentinel_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sentinel_runtime;
