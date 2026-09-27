create schema if not exists net;
create table net.http_request_queue (id bigserial primary key, url text, body jsonb, headers jsonb, timeout_milliseconds int);
create table net._http_response (id bigint primary key, status_code int, error_msg text, timed_out boolean default false, content text, created timestamptz default now());
create function net.http_post(url text, body jsonb default '{}'::jsonb, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb, timeout_milliseconds integer default 5000)
returns bigint language sql as $$ insert into net.http_request_queue (url, body, headers, timeout_milliseconds) values (url, body, headers, timeout_milliseconds) returning id $$;
