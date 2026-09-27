-- Sales and demo inquiries from the public website.
-- Anonymous visitors can only submit through a validated, rate-limited RPC.
-- The table has RLS enabled and no policies: it is readable only by the
-- project owner (dashboard / service role), never through the public API.

create table if not exists public.sales_inquiries (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 2 and 120),
  work_email text not null check (char_length(work_email) between 6 and 254),
  company text not null check (char_length(company) between 2 and 160),
  company_size text not null check (company_size in ('1-10','11-50','51-200','201-1000','1000+')),
  interest text not null check (interest in ('demo','enterprise','security','partnership','support')),
  message text check (message is null or char_length(message) <= 2000),
  source_path text check (source_path is null or char_length(source_path) <= 200),
  email_hash bytea not null,
  status text not null default 'new' check (status in ('new','contacted','qualified','closed'))
);

alter table public.sales_inquiries enable row level security;
revoke all on public.sales_inquiries from anon, authenticated;

create index if not exists sales_inquiries_created_at_idx on public.sales_inquiries (created_at desc);
create index if not exists sales_inquiries_email_hash_idx on public.sales_inquiries (email_hash, created_at desc);

create or replace function private.submit_sales_inquiry(
  p_name text, p_work_email text, p_company text, p_company_size text, p_interest text,
  p_message text, p_source_path text, p_website text
) returns boolean
language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_email text := lower(btrim(coalesce(p_work_email, '')));
  v_hash bytea;
begin
  -- Honeypot: bots fill hidden fields. Pretend success, store nothing.
  if coalesce(btrim(p_website), '') <> '' then
    return true;
  end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]{2,}$' or char_length(v_email) > 254 then
    raise exception 'invalid work email' using errcode = '22023';
  end if;
  if char_length(btrim(coalesce(p_name, ''))) not between 2 and 120
     or char_length(btrim(coalesce(p_company, ''))) not between 2 and 160
     or char_length(coalesce(p_message, '')) > 2000 then
    raise exception 'invalid inquiry' using errcode = '22023';
  end if;
  v_hash := extensions.digest(v_email, 'sha256');
  if (select count(*) from public.sales_inquiries where email_hash = v_hash and created_at > now() - interval '24 hours') >= 3 then
    raise exception 'too many inquiries from this email today' using errcode = 'P0001';
  end if;
  if (select count(*) from public.sales_inquiries where created_at > now() - interval '1 hour') >= 300 then
    raise exception 'inquiries are temporarily rate limited' using errcode = 'P0001';
  end if;
  insert into public.sales_inquiries (name, work_email, company, company_size, interest, message, source_path, email_hash)
  values (btrim(p_name), v_email, btrim(p_company), p_company_size, p_interest,
          nullif(btrim(coalesce(p_message, '')), ''), left(nullif(btrim(coalesce(p_source_path, '')), ''), 200), v_hash);
  return true;
end
$$;
revoke all on function private.submit_sales_inquiry(text,text,text,text,text,text,text,text) from public;
grant execute on function private.submit_sales_inquiry(text,text,text,text,text,text,text,text) to anon, authenticated;

create or replace function public.submit_sales_inquiry(
  p_name text, p_work_email text, p_company text, p_company_size text, p_interest text,
  p_message text default null, p_source_path text default null, p_website text default null
) returns boolean
language sql volatile security invoker set search_path = ''
as $$ select private.submit_sales_inquiry(p_name, p_work_email, p_company, p_company_size, p_interest, p_message, p_source_path, p_website) $$;
revoke all on function public.submit_sales_inquiry(text,text,text,text,text,text,text,text) from public;
grant execute on function public.submit_sales_inquiry(text,text,text,text,text,text,text,text) to anon, authenticated;

-- Retention: inquiries are deleted after two years.
select cron.schedule('px-purge-sales-inquiries', '17 3 * * *',
  $$delete from public.sales_inquiries where created_at < now() - interval '730 days'$$);
