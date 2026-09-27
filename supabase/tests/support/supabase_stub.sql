-- Minimal stand-ins for the Supabase platform schemas (auth, storage, extensions) so
-- the migrations and SQL tests can run on a plain PostgreSQL server in CI.
do $$ begin create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls; create role authenticator login noinherit; grant anon, authenticated, service_role to authenticator; exception when duplicate_object then null; end $$;
create schema extensions; create extension pgcrypto schema extensions; create extension "uuid-ossp" schema extensions;
grant usage on schema extensions to anon, authenticated, service_role;
create schema auth;
create type auth.factor_status as enum ('unverified','verified');
create table auth.users (id uuid primary key, instance_id uuid, aud text, role text, encrypted_password text, updated_at timestamptz default now(), email text, email_confirmed_at timestamptz, phone text, last_sign_in_at timestamptz,
  raw_app_meta_data jsonb default '{}', raw_user_meta_data jsonb default '{}', created_at timestamptz default now(), deleted_at timestamptz, is_anonymous boolean default false);
create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id), status auth.factor_status, factor_type text, friendly_name text, phone text, created_at timestamptz default now());
create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb) $$;
create function auth.uid() returns uuid language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''), nullif(auth.jwt() ->> 'sub', ''))::uuid $$;
create function auth.role() returns text language sql stable as $$ select auth.jwt() ->> 'role' $$;
create function auth.email() returns text language sql stable as $$ select auth.jwt() ->> 'email' $$;
grant usage on schema auth to anon, authenticated, service_role;
create schema storage;
create table storage.buckets (id text primary key, name text, public boolean, file_size_limit bigint, allowed_mime_types text[], owner uuid, created_at timestamptz default now());
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text, owner uuid, metadata jsonb, created_at timestamptz default now());
alter table storage.objects enable row level security;
create function storage.foldername(name text) returns text[] language sql immutable as $$ select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'),1)-1] $$;
grant usage on schema storage to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
