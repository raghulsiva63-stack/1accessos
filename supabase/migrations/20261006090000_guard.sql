-- Passkey-X Guard: web, device and software protection across the browser extension, the
-- desktop app and the mobile app.
--
-- Privacy model ("threats only"):
-- * Pages are checked on the device. Organizations never receive browsing history: only
--   findings (a dangerous site that was warned about or blocked, risky software, a weak device
--   setting) with the site or program name.
-- * Software inventories stay on the device; only risky programs are reported.
-- * Threat lists are hashes. Devices hold 4-byte prefixes and ask the server only about a
--   prefix that matched (see apps/web/lib/security/url-hash.ts).
begin;

-- ---------------------------------------------------------------------------
-- 1. Organization policy
-- ---------------------------------------------------------------------------
create table if not exists public.guard_policies (
  tenant_id uuid primary key references public.tenants(id) on delete cascade,
  web_mode text not null default 'warn' check (web_mode in ('off','warn','block')),
  block_suspicious boolean not null default false,
  require_extension boolean not null default false,
  require_desktop boolean not null default false,
  allow_domains text[] not null default '{}' check (cardinality(allow_domains) <= 500),
  block_domains text[] not null default '{}' check (cardinality(block_domains) <= 2000),
  protected_domains text[] not null default '{}' check (cardinality(protected_domains) <= 50),
  software_block text[] not null default '{}' check (cardinality(software_block) <= 200),
  software_allow text[] not null default '{}' check (cardinality(software_allow) <= 200),
  community_intel boolean not null default true,
  -- Shown on warning pages ("Acme blocks this site"). Organization names are otherwise encrypted.
  organization_name text check (organization_name is null or char_length(organization_name) between 1 and 80),
  updated_by uuid references public.identities(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.guard_policies enable row level security;
revoke all on public.guard_policies from anon, authenticated;
grant select on public.guard_policies to authenticated;
drop policy if exists guard_policies_read on public.guard_policies;
create policy guard_policies_read on public.guard_policies for select to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner','admin','member'])));

-- ---------------------------------------------------------------------------
-- 2. Protected devices and app installs
-- ---------------------------------------------------------------------------
create table if not exists public.guard_endpoints (
  id uuid primary key default gen_random_uuid(),
  identity_id uuid not null references public.identities(id) on delete cascade,
  install_id uuid not null,
  kind text not null check (kind in ('desktop','extension','mobile')),
  platform text not null check (platform in ('windows','macos','linux','android','ios','chrome','edge','brave','chromium','firefox','unknown')),
  label text not null default '' check (char_length(label) <= 80),
  os_version text check (os_version is null or char_length(os_version) <= 60),
  app_version text check (app_version is null or char_length(app_version) <= 30),
  posture jsonb not null default '{}' check (jsonb_typeof(posture) = 'object' and octet_length(posture::text) <= 2000),
  software_total integer check (software_total is null or software_total between 0 and 100000),
  software_risky integer check (software_risky is null or software_risky between 0 and 100000),
  protection_on boolean not null default true,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (identity_id, install_id)
);
create index if not exists guard_endpoints_identity_idx on public.guard_endpoints (identity_id, last_seen_at desc);

-- ---------------------------------------------------------------------------
-- 3. Findings
-- ---------------------------------------------------------------------------
create table if not exists public.guard_findings (
  id bigint generated always as identity primary key,
  identity_id uuid not null references public.identities(id) on delete cascade,
  endpoint_id uuid references public.guard_endpoints(id) on delete set null,
  source text not null check (source in ('extension','desktop','mobile','web')),
  category text not null check (category in ('web','software','device','account')),
  kind text not null check (kind ~ '^[a-z][a-z_]{2,39}$'),
  severity text not null check (severity in ('critical','high','medium','low')),
  subject text not null check (char_length(subject) between 1 and 200),
  detail jsonb not null default '{}' check (jsonb_typeof(detail) = 'object' and octet_length(detail::text) <= 2000),
  action text not null check (action in ('warned','blocked','proceeded','reported','detected')),
  dedupe_key text not null check (char_length(dedupe_key) between 1 and 300),
  status text not null default 'open' check (status in ('open','resolved','dismissed')),
  occurrences integer not null default 1,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by uuid references public.identities(id) on delete set null
);
create unique index if not exists guard_findings_open_key on public.guard_findings (identity_id, dedupe_key) where status = 'open';
create index if not exists guard_findings_identity_idx on public.guard_findings (identity_id, last_seen_at desc);
create index if not exists guard_findings_recent_idx on public.guard_findings (last_seen_at desc);

-- People see their own devices and findings; organization admins see their members' (below).
alter table public.guard_endpoints enable row level security;
alter table public.guard_findings enable row level security;
revoke all on public.guard_endpoints, public.guard_findings from anon, authenticated;
grant select on public.guard_endpoints, public.guard_findings to authenticated;
drop policy if exists guard_endpoints_own on public.guard_endpoints;
create policy guard_endpoints_own on public.guard_endpoints for select to authenticated
  using (identity_id = (select private.current_identity_id()));
drop policy if exists guard_findings_own on public.guard_findings;
create policy guard_findings_own on public.guard_findings for select to authenticated
  using (identity_id = (select private.current_identity_id()));

-- ---------------------------------------------------------------------------
-- 4. Threat intelligence
-- ---------------------------------------------------------------------------
-- Full SHA-256 hashes of URL expressions ("host/path"). tenant_id null = for everyone.
create table if not exists private.threat_indicators (
  id bigint generated always as identity primary key,
  hash bytea not null check (octet_length(hash) = 32),
  prefix bytea generated always as (substring(hash from 1 for 4)) stored,
  threat text not null check (threat in ('phishing','malware','unwanted','blocked')),
  source text not null check (source in ('urlhaus','feed','community','organization')),
  tenant_id uuid references public.tenants(id) on delete cascade,
  expression text check (expression is null or char_length(expression) <= 600),
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create unique index if not exists threat_indicators_unique on private.threat_indicators (source, hash, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));
create index if not exists threat_indicators_prefix_idx on private.threat_indicators (prefix);
revoke all on private.threat_indicators from public, anon, authenticated;

-- Versions of the published prefix list and Web Risk full-hash answers (cached until they expire).
create table if not exists private.threat_intel_state (
  key text primary key,
  value jsonb not null default '{}',
  updated_at timestamptz not null default now()
);
revoke all on private.threat_intel_state from public, anon, authenticated;
create table if not exists private.webrisk_hash_cache (
  prefix bytea primary key check (octet_length(prefix) = 4),
  matches jsonb not null default '[]',
  expires_at timestamptz not null
);
revoke all on private.webrisk_hash_cache from public, anon, authenticated;

-- Pages people reported as phishing. An organization admin confirms or rejects; confirmed sites
-- are blocked for that organization, and a site confirmed by three organizations is blocked for
-- every Passkey-X customer for 30 days (community intelligence).
create table if not exists public.threat_reports (
  id bigint generated always as identity primary key,
  tenant_id uuid references public.tenants(id) on delete cascade,
  identity_id uuid not null references public.identities(id) on delete cascade,
  expression text not null check (char_length(expression) between 3 and 600),
  host text not null check (char_length(host) between 1 and 253),
  hash bytea not null check (octet_length(hash) = 32),
  note text check (note is null or char_length(note) <= 300),
  status text not null default 'pending' check (status in ('pending','confirmed','rejected')),
  reviewed_by uuid references public.identities(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists threat_reports_tenant_idx on public.threat_reports (tenant_id, status, created_at desc);
create unique index if not exists threat_reports_once on public.threat_reports (identity_id, hash) where status = 'pending';
alter table public.threat_reports enable row level security;
revoke all on public.threat_reports from anon, authenticated;
grant select on public.threat_reports to authenticated;
drop policy if exists threat_reports_own on public.threat_reports;
create policy threat_reports_own on public.threat_reports for select to authenticated
  using (identity_id = (select private.current_identity_id()));

insert into storage.buckets (id, name, public, file_size_limit)
values ('threat-intel', 'threat-intel', false, 52428800)
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
-- 5. Helpers
-- ---------------------------------------------------------------------------
-- Organizations whose Guard dashboard may show this person's devices and findings.
create or replace function private.can_view_member_guard(p_identity uuid)
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.tenant_memberships tm join public.tenants t on t.id = tm.tenant_id
    where tm.identity_id = p_identity and tm.status = 'active' and t.kind = 'organization'
      and private.can_view_security_posture(tm.tenant_id)
  )
$$;
revoke all on function private.can_view_member_guard(uuid) from public, anon;
grant execute on function private.can_view_member_guard(uuid) to authenticated;

drop policy if exists guard_endpoints_admin on public.guard_endpoints;
create policy guard_endpoints_admin on public.guard_endpoints for select to authenticated
  using ((select private.can_view_member_guard(identity_id)));
drop policy if exists guard_findings_admin on public.guard_findings;
create policy guard_findings_admin on public.guard_findings for select to authenticated
  using ((select private.can_view_member_guard(identity_id)));

create or replace function private.require_guard_admin(p_tenant uuid)
returns uuid language plpgsql stable security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id();
begin
  if v_actor is null or not private.has_business_entitlement(p_tenant)
     or not private.can_manage_organization(p_tenant, array['organization_admin','security_admin']) then
    raise exception 'security administrator required' using errcode = '42501';
  end if;
  return v_actor;
end
$$;
revoke all on function private.require_guard_admin(uuid) from public, anon, authenticated;

create or replace function private.clean_domains(p_values text[], p_limit integer)
returns text[] language sql immutable set search_path = ''
as $$
  select coalesce(array_agg(d order by d), '{}') from (
    select distinct lower(regexp_replace(regexp_replace(trim(v), '^(\*\.|https?://)', ''), '[/:].*$', '')) as d
    from unnest(coalesce(p_values, '{}')) v
  ) s
  where d ~ '^([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$' and char_length(d) <= 253
  limit p_limit
$$;

create or replace function private.clean_names(p_values text[], p_limit integer)
returns text[] language sql immutable set search_path = ''
as $$
  select coalesce(array_agg(n order by n), '{}') from (
    select distinct lower(trim(v)) as n from unnest(coalesce(p_values, '{}')) v
  ) s
  where char_length(n) between 2 and 80 and n !~ '[[:cntrl:]]'
  limit p_limit
$$;

-- ---------------------------------------------------------------------------
-- 6. Policy RPCs
-- ---------------------------------------------------------------------------
-- The policy in effect for the signed-in person: the strictest of their organizations' policies.
create or replace function private.my_guard_policy()
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_result jsonb;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  select jsonb_build_object(
    'webMode', coalesce((array_agg(p.web_mode order by case p.web_mode when 'block' then 0 when 'warn' then 1 else 2 end))[1], 'warn'),
    'blockSuspicious', coalesce(bool_or(p.block_suspicious), false),
    'requireExtension', coalesce(bool_or(p.require_extension), false),
    'requireDesktop', coalesce(bool_or(p.require_desktop), false),
    'allowDomains', coalesce((select jsonb_agg(distinct d) from public.guard_policies p2 join public.tenant_memberships m2
        on m2.tenant_id = p2.tenant_id and m2.identity_id = v_actor and m2.status = 'active', unnest(p2.allow_domains) d), '[]'),
    'blockDomains', coalesce((select jsonb_agg(distinct d) from public.guard_policies p2 join public.tenant_memberships m2
        on m2.tenant_id = p2.tenant_id and m2.identity_id = v_actor and m2.status = 'active', unnest(p2.block_domains) d), '[]'),
    'protectedDomains', coalesce((select jsonb_agg(distinct d) from public.guard_policies p2 join public.tenant_memberships m2
        on m2.tenant_id = p2.tenant_id and m2.identity_id = v_actor and m2.status = 'active', unnest(p2.protected_domains) d), '[]'),
    'softwareBlock', coalesce((select jsonb_agg(distinct d) from public.guard_policies p2 join public.tenant_memberships m2
        on m2.tenant_id = p2.tenant_id and m2.identity_id = v_actor and m2.status = 'active', unnest(p2.software_block) d), '[]'),
    'softwareAllow', coalesce((select jsonb_agg(distinct d) from public.guard_policies p2 join public.tenant_memberships m2
        on m2.tenant_id = p2.tenant_id and m2.identity_id = v_actor and m2.status = 'active', unnest(p2.software_allow) d), '[]'),
    'communityIntel', coalesce(bool_and(p.community_intel), true),
    'organizationName', (array_agg(p.organization_name order by p.updated_at) filter (where p.organization_name is not null))[1],
    'managed', count(p.tenant_id) > 0)
  into v_result
  from public.tenant_memberships m
  left join public.guard_policies p on p.tenant_id = m.tenant_id
  where m.identity_id = v_actor and m.status = 'active';
  return v_result;
end
$$;

create or replace function private.set_guard_policy(p_tenant_id uuid, p_policy jsonb)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.require_guard_admin(p_tenant_id);
  v_mode text := coalesce(p_policy ->> 'webMode', 'warn');
  v_array text[];
begin
  if jsonb_typeof(p_policy) <> 'object' or v_mode not in ('off','warn','block') then
    raise exception 'invalid policy' using errcode = '22023';
  end if;
  insert into public.guard_policies as g (tenant_id, web_mode, block_suspicious, require_extension, require_desktop,
    allow_domains, block_domains, protected_domains, software_block, software_allow, community_intel, organization_name, updated_by, updated_at)
  values (p_tenant_id, v_mode,
    coalesce((p_policy ->> 'blockSuspicious')::boolean, false),
    coalesce((p_policy ->> 'requireExtension')::boolean, false),
    coalesce((p_policy ->> 'requireDesktop')::boolean, false),
    private.clean_domains(array(select jsonb_array_elements_text(coalesce(p_policy -> 'allowDomains', '[]'))), 500),
    private.clean_domains(array(select jsonb_array_elements_text(coalesce(p_policy -> 'blockDomains', '[]'))), 2000),
    private.clean_domains(array(select jsonb_array_elements_text(coalesce(p_policy -> 'protectedDomains', '[]'))), 50),
    private.clean_names(array(select jsonb_array_elements_text(coalesce(p_policy -> 'softwareBlock', '[]'))), 200),
    private.clean_names(array(select jsonb_array_elements_text(coalesce(p_policy -> 'softwareAllow', '[]'))), 200),
    coalesce((p_policy ->> 'communityIntel')::boolean, true),
    nullif(left(trim(regexp_replace(coalesce(p_policy ->> 'organizationName', ''), '[[:cntrl:]]', '', 'g')), 80), ''), v_actor, now())
  on conflict (tenant_id) do update set web_mode = excluded.web_mode, block_suspicious = excluded.block_suspicious,
    require_extension = excluded.require_extension, require_desktop = excluded.require_desktop,
    allow_domains = excluded.allow_domains, block_domains = excluded.block_domains,
    protected_domains = excluded.protected_domains, software_block = excluded.software_block,
    software_allow = excluded.software_allow, community_intel = excluded.community_intel, organization_name = excluded.organization_name,
    updated_by = excluded.updated_by, updated_at = now();
  perform private.append_audit_event(p_tenant_id, null, 'guard.policy_updated', 'guard_policies', null,
    jsonb_build_object('web_mode', v_mode));
end
$$;

-- ---------------------------------------------------------------------------
-- 7. Device and finding reports (from the apps)
-- ---------------------------------------------------------------------------
create or replace function private.report_guard_endpoint(
  p_install_id uuid, p_kind text, p_platform text, p_label text, p_os_version text, p_app_version text,
  p_posture jsonb, p_software_total integer default null, p_software_risky integer default null, p_protection_on boolean default true
) returns uuid language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_id uuid;
  v_key text;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  if p_install_id is null or p_kind not in ('desktop','extension','mobile') then raise exception 'invalid report' using errcode = '22023'; end if;
  if jsonb_typeof(coalesce(p_posture, '{}')) <> 'object' then raise exception 'invalid report' using errcode = '22023'; end if;
  for v_key in select jsonb_object_keys(coalesce(p_posture, '{}')) loop
    if not (v_key = any(array['disk_encrypted','firewall','screen_lock','os_supported','os_updates','auto_updates','rooted',
        'developer_mode','usb_debugging','patch_age_days','browser_protection','secure_boot','antivirus','unknown_sources'])) then
      raise exception 'invalid report' using errcode = '22023';
    end if;
  end loop;
  insert into public.guard_endpoints as e (identity_id, install_id, kind, platform, label, os_version, app_version, posture,
    software_total, software_risky, protection_on, last_seen_at)
  values (v_actor, p_install_id, p_kind,
    case when p_platform in ('windows','macos','linux','android','ios','chrome','edge','brave','chromium','firefox') then p_platform else 'unknown' end,
    left(coalesce(regexp_replace(p_label, '[[:cntrl:]]', '', 'g'), ''), 80), left(p_os_version, 60), left(p_app_version, 30),
    coalesce(p_posture, '{}'), p_software_total, p_software_risky, coalesce(p_protection_on, true), now())
  on conflict (identity_id, install_id) do update set kind = excluded.kind, platform = excluded.platform, label = excluded.label,
    os_version = excluded.os_version, app_version = excluded.app_version, posture = excluded.posture,
    software_total = coalesce(excluded.software_total, e.software_total), software_risky = coalesce(excluded.software_risky, e.software_risky),
    protection_on = excluded.protection_on, last_seen_at = now()
  returning e.id into v_id;
  return v_id;
end
$$;

-- p_findings: [{ source, category, kind, severity, subject, detail, action, key }] (at most 50).
create or replace function private.report_guard_findings(p_install_id uuid, p_findings jsonb)
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_endpoint uuid;
  v_item jsonb;
  v_count integer := 0;
  v_recent integer;
  v_key text;
  v_tenant uuid;
  v_title text;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  if jsonb_typeof(p_findings) <> 'array' or jsonb_array_length(p_findings) > 50 then raise exception 'invalid report' using errcode = '22023'; end if;
  select count(*) into v_recent from public.guard_findings f where f.identity_id = v_actor and f.last_seen_at > now() - interval '1 hour';
  if v_recent > 600 then raise exception 'too many reports' using errcode = '54000'; end if;
  select e.id into v_endpoint from public.guard_endpoints e where e.identity_id = v_actor and e.install_id = p_install_id;
  for v_item in select value from jsonb_array_elements(p_findings) loop
    if jsonb_typeof(v_item) <> 'object' then raise exception 'invalid report' using errcode = '22023'; end if;
    v_key := left(coalesce(nullif(v_item ->> 'key', ''), (v_item ->> 'kind') || ':' || (v_item ->> 'subject')), 300);
    begin
      insert into public.guard_findings as f (identity_id, endpoint_id, source, category, kind, severity, subject, detail, action, dedupe_key)
      values (v_actor, v_endpoint, v_item ->> 'source', v_item ->> 'category', v_item ->> 'kind', v_item ->> 'severity',
        left(v_item ->> 'subject', 200), coalesce(v_item -> 'detail', '{}'), v_item ->> 'action', v_key)
      on conflict (identity_id, dedupe_key) where status = 'open' do update set
        occurrences = f.occurrences + 1, last_seen_at = now(), endpoint_id = coalesce(excluded.endpoint_id, f.endpoint_id),
        severity = excluded.severity, action = excluded.action, detail = excluded.detail;
    exception when check_violation or not_null_violation or invalid_text_representation then
      raise exception 'invalid report' using errcode = '22023';
    end;
    v_count := v_count + 1;
    -- Serious findings also become organization security alerts (and admin emails).
    if v_item ->> 'severity' in ('critical','high') then
      v_title := case v_item ->> 'category'
        when 'web' then 'Dangerous website: ' || left(v_item ->> 'subject', 120)
        when 'software' then 'Risky software: ' || left(v_item ->> 'subject', 120)
        when 'device' then 'Unsafe device setting: ' || left(v_item ->> 'subject', 120)
        else left(v_item ->> 'subject', 150) end;
      for v_tenant in select private.org_tenants_of(v_actor) loop
        perform private.raise_security_alert(v_tenant, v_item ->> 'severity', left('guard.' || (v_item ->> 'kind'), 60), v_title,
          jsonb_build_object('identity_id', v_actor, 'subject', left(v_item ->> 'subject', 200), 'action', v_item ->> 'action',
            'source', v_item ->> 'source'),
          v_actor, null, 'guard:' || v_actor || ':' || md5(v_key) || ':' || to_char(now(), 'YYYY-MM-DD'));
      end loop;
    end if;
  end loop;
  return v_count;
end
$$;

-- Marks this install's open device/software findings as fixed (for example the firewall is on now).
create or replace function private.resolve_guard_findings(p_install_id uuid, p_keys text[])
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.current_identity_id(); v_count integer;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  update public.guard_findings f set status = 'resolved', resolved_at = now(), resolved_by = v_actor
  where f.identity_id = v_actor and f.status = 'open' and f.dedupe_key = any(coalesce(p_keys, '{}'))
    and f.category in ('software','device')
    and f.endpoint_id = (select e.id from public.guard_endpoints e where e.identity_id = v_actor and e.install_id = p_install_id);
  get diagnostics v_count = row_count;
  return v_count;
end
$$;

-- ---------------------------------------------------------------------------
-- 8. Threat lists
-- ---------------------------------------------------------------------------
-- Full hashes for prefixes that matched on a device: global lists, community intelligence (when
-- the organization allows it) and the person's organizations' own confirmed reports.
create or replace function private.threat_matches(p_prefixes text[])
returns table (hash text, threat text, source text)
language plpgsql stable security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_prefixes bytea[];
  v_community boolean;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  if cardinality(p_prefixes) > 64 then raise exception 'too many prefixes' using errcode = '22023'; end if;
  select array_agg(decode(p, 'base64')) into v_prefixes from unnest(p_prefixes) p;
  if exists (select 1 from unnest(v_prefixes) p where octet_length(p) <> 4) then raise exception 'invalid prefix' using errcode = '22023'; end if;
  v_community := coalesce((private.my_guard_policy() ->> 'communityIntel')::boolean, true);
  return query
    select encode(i.hash, 'base64'), i.threat,
      case i.source when 'urlhaus' then 'URLhaus' when 'feed' then 'threat feed' when 'community' then 'Passkey-X community'
        else 'your organization' end
    from private.threat_indicators i
    where i.prefix = any(v_prefixes)
      and (i.expires_at is null or i.expires_at > now())
      and (i.tenant_id is null or i.tenant_id in (select tm.tenant_id from public.tenant_memberships tm
            where tm.identity_id = v_actor and tm.status = 'active'))
      and (i.source <> 'community' or v_community)
    limit 200;
end
$$;

-- Prefixes of the person's organizations' own indicators (small; merged into the device list).
create or replace function private.my_threat_prefixes()
returns text[] language sql stable security definer set search_path = ''
as $$
  select coalesce(array_agg(distinct encode(i.prefix, 'base64')), '{}')
  from private.threat_indicators i
  where i.tenant_id in (select tm.tenant_id from public.tenant_memberships tm
      where tm.identity_id = private.current_identity_id() and tm.status = 'active')
    and (i.expires_at is null or i.expires_at > now())
$$;

-- Service role (threat-sync): replaces one feed's indicators.
create or replace function private.replace_threat_feed(p_source text, p_threat text, p_hashes text[], p_expressions text[] default null)
returns integer language plpgsql volatile security definer set search_path = ''
as $$
declare v_count integer;
begin
  if p_source not in ('urlhaus','feed') or p_threat not in ('phishing','malware','unwanted') then
    raise exception 'invalid feed' using errcode = '22023';
  end if;
  delete from private.threat_indicators where source = p_source and threat = p_threat and tenant_id is null;
  insert into private.threat_indicators (hash, threat, source, expression)
  select decode(h, 'base64'), p_threat, p_source, left(p_expressions[n], 600)
  from unnest(p_hashes) with ordinality as x(h, n)
  where octet_length(decode(h, 'base64')) = 32
  on conflict do nothing;
  get diagnostics v_count = row_count;
  return v_count;
end
$$;

-- Service role: every prefix that applies to everyone (published to devices with the Web Risk list).
create or replace function private.global_threat_prefixes()
returns text[] language sql stable security definer set search_path = ''
as $$
  select coalesce(array_agg(distinct encode(i.prefix, 'base64')), '{}')
  from private.threat_indicators i
  where i.tenant_id is null and (i.expires_at is null or i.expires_at > now())
$$;

create or replace function private.set_threat_intel_state(p_key text, p_value jsonb)
returns void language sql volatile security definer set search_path = ''
as $$
  insert into private.threat_intel_state (key, value, updated_at) values (p_key, p_value, now())
  on conflict (key) do update set value = excluded.value, updated_at = now()
$$;

create or replace function private.get_threat_intel_state(p_key text)
returns jsonb language sql stable security definer set search_path = ''
as $$ select s.value from private.threat_intel_state s where s.key = p_key $$;

create or replace function private.webrisk_cached(p_prefixes text[])
returns table (prefix text, matches jsonb)
language sql stable security definer set search_path = ''
as $$
  select encode(c.prefix, 'base64'), c.matches from private.webrisk_hash_cache c
  where c.prefix = any(array(select decode(p, 'base64') from unnest(p_prefixes) p)) and c.expires_at > now()
$$;

create or replace function private.webrisk_store(p_prefix text, p_matches jsonb, p_seconds integer)
returns void language sql volatile security definer set search_path = ''
as $$
  insert into private.webrisk_hash_cache (prefix, matches, expires_at)
  values (decode(p_prefix, 'base64'), coalesce(p_matches, '[]'), now() + make_interval(secs => greatest(60, least(p_seconds, 86400))))
  on conflict (prefix) do update set matches = excluded.matches, expires_at = excluded.expires_at
$$;

-- Report a page as phishing (sent by the person, with the address they chose to report).
create or replace function private.report_phishing(p_expression text, p_host text, p_hash text, p_note text default null)
returns bigint language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.current_identity_id();
  v_tenant uuid;
  v_id bigint;
begin
  if v_actor is null then raise exception 'sign-in required' using errcode = '42501'; end if;
  if p_host !~ '^[a-z0-9.-]{1,253}$' or octet_length(decode(p_hash, 'base64')) <> 32 or char_length(p_expression) not between 3 and 600 then
    raise exception 'invalid report' using errcode = '22023';
  end if;
  if (select count(*) from public.threat_reports r where r.identity_id = v_actor and r.created_at > now() - interval '1 day') >= 50 then
    raise exception 'too many reports' using errcode = '54000';
  end if;
  select t into v_tenant from private.org_tenants_of(v_actor) t limit 1;
  insert into public.threat_reports (tenant_id, identity_id, expression, host, hash, note)
  values (v_tenant, v_actor, p_expression, p_host, decode(p_hash, 'base64'), left(p_note, 300))
  on conflict (identity_id, hash) where status = 'pending' do nothing
  returning id into v_id;
  return v_id;
end
$$;

create or replace function private.review_threat_report(p_tenant_id uuid, p_report_id bigint, p_confirm boolean)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_actor uuid := private.require_guard_admin(p_tenant_id);
  v_report public.threat_reports%rowtype;
  v_confirming integer;
begin
  select * into v_report from public.threat_reports r where r.id = p_report_id and r.tenant_id = p_tenant_id for update;
  if not found then raise exception 'report not found' using errcode = 'P0002'; end if;
  update public.threat_reports set status = case when p_confirm then 'confirmed' else 'rejected' end,
    reviewed_by = v_actor, reviewed_at = now() where id = p_report_id;
  if p_confirm then
    insert into private.threat_indicators (hash, threat, source, tenant_id, expression)
    values (v_report.hash, 'phishing', 'organization', p_tenant_id, v_report.expression) on conflict do nothing;
    -- Confirmed by three different organizations: block for everyone for 30 days.
    select count(distinct r.tenant_id) into v_confirming from public.threat_reports r
    where r.hash = v_report.hash and r.status = 'confirmed' and r.tenant_id is not null;
    if v_confirming >= 3 then
      insert into private.threat_indicators (hash, threat, source, expression, expires_at)
      values (v_report.hash, 'phishing', 'community', v_report.expression, now() + interval '30 days')
      on conflict (source, hash, coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid))
      do update set expires_at = now() + interval '30 days';
    end if;
  end if;
  perform private.append_audit_event(p_tenant_id, null, 'guard.threat_report_reviewed', 'threat_reports', null,
    jsonb_build_object('host', v_report.host, 'confirmed', p_confirm));
end
$$;

-- ---------------------------------------------------------------------------
-- 9. Dashboards
-- ---------------------------------------------------------------------------
create or replace function private.organization_guard_overview(p_tenant_id uuid)
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare v_result jsonb;
begin
  if not private.can_view_security_posture(p_tenant_id) then raise exception 'not allowed' using errcode = '42501'; end if;
  with members as (
    select tm.identity_id from public.tenant_memberships tm where tm.tenant_id = p_tenant_id and tm.status = 'active'
  ), findings as (
    select f.* from public.guard_findings f join members m on m.identity_id = f.identity_id
  ), endpoints as (
    select e.* from public.guard_endpoints e join members m on m.identity_id = e.identity_id
    where e.last_seen_at > now() - interval '30 days'
  )
  select jsonb_build_object(
    'members', (select count(*) from members),
    'open', jsonb_build_object(
      'critical', (select count(*) from findings where status = 'open' and severity = 'critical'),
      'high', (select count(*) from findings where status = 'open' and severity = 'high'),
      'medium', (select count(*) from findings where status = 'open' and severity = 'medium'),
      'low', (select count(*) from findings where status = 'open' and severity = 'low')),
    'last7Days', jsonb_build_object(
      'blocked', (select coalesce(sum(occurrences), 0) from findings where category = 'web' and action = 'blocked' and last_seen_at > now() - interval '7 days'),
      'warned', (select coalesce(sum(occurrences), 0) from findings where category = 'web' and action = 'warned' and last_seen_at > now() - interval '7 days'),
      'proceeded', (select coalesce(sum(occurrences), 0) from findings where category = 'web' and action = 'proceeded' and last_seen_at > now() - interval '7 days'),
      'reported', (select count(*) from public.threat_reports r where r.tenant_id = p_tenant_id and r.created_at > now() - interval '7 days')),
    'coverage', jsonb_build_object(
      'desktop', (select count(distinct identity_id) from endpoints where kind = 'desktop' and protection_on),
      'extension', (select count(distinct identity_id) from endpoints where kind = 'extension' and protection_on),
      'mobile', (select count(distinct identity_id) from endpoints where kind = 'mobile' and protection_on),
      'any', (select count(distinct identity_id) from endpoints where protection_on)),
    'devices', jsonb_build_object(
      'total', (select count(*) from endpoints where kind in ('desktop','mobile')),
      'atRisk', (select count(*) from endpoints e where e.kind in ('desktop','mobile') and exists (
          select 1 from findings f where f.endpoint_id = e.id and f.status = 'open' and f.severity in ('critical','high')))),
    'pendingReports', (select count(*) from public.threat_reports r where r.tenant_id = p_tenant_id and r.status = 'pending'),
    'policy', coalesce((select to_jsonb(p) - 'tenant_id' - 'updated_by' from public.guard_policies p where p.tenant_id = p_tenant_id), '{}'::jsonb)
  ) into v_result;
  return v_result;
end
$$;

create or replace function private.organization_guard_findings(p_tenant_id uuid, p_status text default 'open', p_category text default null, p_limit integer default 200)
returns table (id bigint, identity_id uuid, member_email text, member_name text, endpoint_label text, platform text,
  source text, category text, kind text, severity text, subject text, detail jsonb, action text, status text,
  occurrences integer, first_seen_at timestamptz, last_seen_at timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then raise exception 'not allowed' using errcode = '42501'; end if;
  return query
    select f.id, f.identity_id, u.email::text, coalesce(op.display_name, split_part(u.email::text, '@', 1)), e.label, e.platform,
      f.source, f.category, f.kind, f.severity, f.subject, f.detail, f.action, f.status, f.occurrences, f.first_seen_at, f.last_seen_at
    from public.guard_findings f
    join public.tenant_memberships tm on tm.identity_id = f.identity_id and tm.tenant_id = p_tenant_id and tm.status = 'active'
    join public.identities i on i.id = f.identity_id
    left join auth.users u on u.id = i.auth_user_id
    left join public.organization_profiles op on op.tenant_id = p_tenant_id and op.identity_id = f.identity_id
    left join public.guard_endpoints e on e.id = f.endpoint_id
    where (p_status is null or f.status = p_status) and (p_category is null or f.category = p_category)
    order by case f.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end, f.last_seen_at desc
    limit least(greatest(coalesce(p_limit, 200), 1), 500);
end
$$;

create or replace function private.organization_guard_endpoints(p_tenant_id uuid)
returns table (id uuid, identity_id uuid, member_email text, member_name text, kind text, platform text, label text,
  os_version text, app_version text, posture jsonb, software_total integer, software_risky integer, protection_on boolean,
  open_findings integer, last_seen_at timestamptz)
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not private.can_view_security_posture(p_tenant_id) then raise exception 'not allowed' using errcode = '42501'; end if;
  return query
    select e.id, e.identity_id, u.email::text, coalesce(op.display_name, split_part(u.email::text, '@', 1)), e.kind, e.platform, e.label,
      e.os_version, e.app_version, e.posture, e.software_total, e.software_risky, e.protection_on,
      (select count(*)::integer from public.guard_findings f where f.endpoint_id = e.id and f.status = 'open'), e.last_seen_at
    from public.guard_endpoints e
    join public.tenant_memberships tm on tm.identity_id = e.identity_id and tm.tenant_id = p_tenant_id and tm.status = 'active'
    join public.identities i on i.id = e.identity_id
    left join auth.users u on u.id = i.auth_user_id
    left join public.organization_profiles op on op.tenant_id = p_tenant_id and op.identity_id = e.identity_id
    order by e.last_seen_at desc
    limit 2000;
end
$$;

create or replace function private.set_guard_finding_status(p_tenant_id uuid, p_finding_id bigint, p_status text)
returns void language plpgsql volatile security definer set search_path = ''
as $$
declare v_actor uuid := private.require_guard_admin(p_tenant_id);
begin
  if p_status not in ('open','resolved','dismissed') then raise exception 'invalid status' using errcode = '22023'; end if;
  update public.guard_findings f set status = p_status,
    resolved_at = case when p_status = 'open' then null else now() end,
    resolved_by = case when p_status = 'open' then null else v_actor end
  where f.id = p_finding_id and exists (select 1 from public.tenant_memberships tm
    where tm.tenant_id = p_tenant_id and tm.identity_id = f.identity_id and tm.status = 'active');
  if not found then raise exception 'finding not found' using errcode = 'P0002'; end if;
end
$$;

create or replace function private.organization_threat_reports(p_tenant_id uuid, p_status text default 'pending')
returns table (id bigint, member_email text, expression text, host text, note text, status text, created_at timestamptz,
  confirmed_elsewhere integer)
language plpgsql stable security definer set search_path = ''
as $$
begin
  perform private.require_guard_admin(p_tenant_id);
  return query
    select r.id, u.email::text, r.expression, r.host, r.note, r.status, r.created_at,
      (select count(distinct r2.tenant_id)::integer from public.threat_reports r2 where r2.hash = r.hash and r2.status = 'confirmed' and r2.tenant_id <> p_tenant_id)
    from public.threat_reports r join public.identities i on i.id = r.identity_id
    left join auth.users u on u.id = i.auth_user_id
    where r.tenant_id = p_tenant_id and (p_status is null or r.status = p_status)
    order by r.created_at desc limit 200;
end
$$;

-- Retention: resolved findings after 90 days, any finding after 365 days, reviewed reports after 180 days.
create or replace function private.prune_guard_data()
returns void language sql volatile security definer set search_path = ''
as $$
  delete from public.guard_findings where (status <> 'open' and coalesce(resolved_at, last_seen_at) < now() - interval '90 days')
    or last_seen_at < now() - interval '365 days';
  delete from public.threat_reports where status <> 'pending' and reviewed_at < now() - interval '180 days';
  delete from public.guard_endpoints where last_seen_at < now() - interval '180 days';
  delete from private.threat_indicators where expires_at is not null and expires_at < now() - interval '1 day';
  delete from private.webrisk_hash_cache where expires_at < now();
$$;

-- ---------------------------------------------------------------------------
-- 10. Background sync
-- ---------------------------------------------------------------------------
alter table private.dispatch_tokens drop constraint if exists dispatch_tokens_purpose_check;
alter table private.dispatch_tokens add constraint dispatch_tokens_purpose_check
  check (purpose in ('notify','breach_watch','threat_sync'));
insert into private.app_settings (key, value)
values ('threat_sync_url', 'https://wkkmyacbhqloubtwvjom.supabase.co/functions/v1/threat-sync')
on conflict (key) do nothing;

create or replace function private.kick_threat_sync()
returns void language sql volatile security definer set search_path = ''
as $$ select private.kick_worker('threat_sync', 'threat_sync_url'); $$;

create or replace function private.claim_threat_sync(p_token text)
returns boolean language sql volatile security definer set search_path = ''
as $$ select private.consume_dispatch_token('threat_sync', p_token) $$;

-- ---------------------------------------------------------------------------
-- 11. Public API
-- ---------------------------------------------------------------------------
create or replace function public.my_guard_policy()
returns jsonb language sql stable security invoker set search_path = ''
as $$ select private.my_guard_policy() $$;
create or replace function public.set_guard_policy(p_tenant_id uuid, p_policy jsonb)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_guard_policy(p_tenant_id, p_policy) $$;
create or replace function public.report_guard_endpoint(p_install_id uuid, p_kind text, p_platform text, p_label text,
  p_os_version text, p_app_version text, p_posture jsonb, p_software_total integer default null, p_software_risky integer default null,
  p_protection_on boolean default true)
returns uuid language sql volatile security invoker set search_path = ''
as $$ select private.report_guard_endpoint(p_install_id, p_kind, p_platform, p_label, p_os_version, p_app_version, p_posture,
  p_software_total, p_software_risky, p_protection_on) $$;
create or replace function public.report_guard_findings(p_install_id uuid, p_findings jsonb)
returns integer language sql volatile security invoker set search_path = ''
as $$ select private.report_guard_findings(p_install_id, p_findings) $$;
create or replace function public.resolve_guard_findings(p_install_id uuid, p_keys text[])
returns integer language sql volatile security invoker set search_path = ''
as $$ select private.resolve_guard_findings(p_install_id, p_keys) $$;
create or replace function public.threat_matches(p_prefixes text[])
returns table (hash text, threat text, source text) language sql stable security invoker set search_path = ''
as $$ select * from private.threat_matches(p_prefixes) $$;
create or replace function public.my_threat_prefixes()
returns text[] language sql stable security invoker set search_path = ''
as $$ select private.my_threat_prefixes() $$;
create or replace function public.report_phishing(p_expression text, p_host text, p_hash text, p_note text default null)
returns bigint language sql volatile security invoker set search_path = ''
as $$ select private.report_phishing(p_expression, p_host, p_hash, p_note) $$;
create or replace function public.review_threat_report(p_tenant_id uuid, p_report_id bigint, p_confirm boolean)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.review_threat_report(p_tenant_id, p_report_id, p_confirm) $$;
create or replace function public.organization_guard_overview(p_tenant_id uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select private.organization_guard_overview(p_tenant_id) $$;
create or replace function public.organization_guard_findings(p_tenant_id uuid, p_status text default 'open', p_category text default null, p_limit integer default 200)
returns table (id bigint, identity_id uuid, member_email text, member_name text, endpoint_label text, platform text,
  source text, category text, kind text, severity text, subject text, detail jsonb, action text, status text,
  occurrences integer, first_seen_at timestamptz, last_seen_at timestamptz)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_guard_findings(p_tenant_id, p_status, p_category, p_limit) $$;
create or replace function public.organization_guard_endpoints(p_tenant_id uuid)
returns table (id uuid, identity_id uuid, member_email text, member_name text, kind text, platform text, label text,
  os_version text, app_version text, posture jsonb, software_total integer, software_risky integer, protection_on boolean,
  open_findings integer, last_seen_at timestamptz)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_guard_endpoints(p_tenant_id) $$;
create or replace function public.set_guard_finding_status(p_tenant_id uuid, p_finding_id bigint, p_status text)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_guard_finding_status(p_tenant_id, p_finding_id, p_status) $$;
create or replace function public.organization_threat_reports(p_tenant_id uuid, p_status text default 'pending')
returns table (id bigint, member_email text, expression text, host text, note text, status text, created_at timestamptz,
  confirmed_elsewhere integer)
language sql stable security invoker set search_path = ''
as $$ select * from private.organization_threat_reports(p_tenant_id, p_status) $$;
-- Service role only (threat-sync / threat-check edge functions).
create or replace function public.replace_threat_feed(p_source text, p_threat text, p_hashes text[], p_expressions text[] default null)
returns integer language sql volatile security invoker set search_path = ''
as $$ select private.replace_threat_feed(p_source, p_threat, p_hashes, p_expressions) $$;
create or replace function public.global_threat_prefixes()
returns text[] language sql stable security invoker set search_path = ''
as $$ select private.global_threat_prefixes() $$;
create or replace function public.set_threat_intel_state(p_key text, p_value jsonb)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.set_threat_intel_state(p_key, p_value) $$;
create or replace function public.get_threat_intel_state(p_key text)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select private.get_threat_intel_state(p_key) $$;
create or replace function public.webrisk_cached(p_prefixes text[])
returns table (prefix text, matches jsonb) language sql stable security invoker set search_path = ''
as $$ select * from private.webrisk_cached(p_prefixes) $$;
create or replace function public.webrisk_store(p_prefix text, p_matches jsonb, p_seconds integer)
returns void language sql volatile security invoker set search_path = ''
as $$ select private.webrisk_store(p_prefix, p_matches, p_seconds) $$;
create or replace function public.claim_threat_sync(p_token text)
returns boolean language sql volatile security invoker set search_path = ''
as $$ select private.claim_threat_sync(p_token) $$;

do $$
declare v_sig text;
begin
  foreach v_sig in array array[
    'my_guard_policy()', 'set_guard_policy(uuid,jsonb)',
    'report_guard_endpoint(uuid,text,text,text,text,text,jsonb,integer,integer,boolean)',
    'report_guard_findings(uuid,jsonb)', 'resolve_guard_findings(uuid,text[])', 'threat_matches(text[])', 'my_threat_prefixes()',
    'report_phishing(text,text,text,text)', 'review_threat_report(uuid,bigint,boolean)', 'organization_guard_overview(uuid)',
    'organization_guard_findings(uuid,text,text,integer)', 'organization_guard_endpoints(uuid)',
    'set_guard_finding_status(uuid,bigint,text)', 'organization_threat_reports(uuid,text)'
  ] loop
    execute format('revoke all on function private.%s from public, anon', v_sig);
    execute format('grant execute on function private.%s to authenticated', v_sig);
    execute format('revoke all on function public.%s from public, anon', v_sig);
    execute format('grant execute on function public.%s to authenticated', v_sig);
  end loop;
  foreach v_sig in array array[
    'replace_threat_feed(text,text,text[],text[])', 'global_threat_prefixes()', 'set_threat_intel_state(text,jsonb)',
    'get_threat_intel_state(text)', 'webrisk_cached(text[])', 'webrisk_store(text,jsonb,integer)', 'claim_threat_sync(text)'
  ] loop
    execute format('revoke all on function private.%s from public, anon, authenticated', v_sig);
    execute format('grant execute on function private.%s to service_role', v_sig);
    execute format('revoke all on function public.%s from public, anon, authenticated', v_sig);
    execute format('grant execute on function public.%s to service_role', v_sig);
  end loop;
end
$$;
revoke all on function private.clean_domains(text[],integer), private.clean_names(text[],integer),
  private.kick_threat_sync(), private.prune_guard_data() from public, anon, authenticated;
grant usage on schema private to service_role;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('px-threat-sync', '17 */6 * * *', $cron$select private.kick_threat_sync()$cron$);
    perform cron.schedule('px-guard-prune', '40 3 * * *', $cron$select private.prune_guard_data()$cron$);
  end if;
end
$$;

comment on table public.guard_findings is 'Guard findings: dangerous sites warned about or blocked, risky software, unsafe device settings. Never browsing history.';
comment on table public.guard_endpoints is 'Devices and app installs protected by Passkey-X Guard, with security posture flags.';
comment on table public.threat_reports is 'Pages people reported as phishing, reviewed by their organization.';

commit;
