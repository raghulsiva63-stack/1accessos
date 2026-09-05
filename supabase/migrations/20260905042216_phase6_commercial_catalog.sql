begin;

-- Phase 6 commercial experience checkpoint. The catalog is public product
-- metadata only. It never contains Stripe secrets, customer billing records,
-- vault ciphertext, keys, or identity data. Published versions are append-only:
-- changing price or entitlement terms requires a new catalog version.
create table public.plan_catalog (
  catalog_version text not null,
  plan_code text not null,
  display_name text not null check (length(display_name) between 2 and 80),
  audience text not null check (length(audience) between 2 and 160),
  summary text not null check (length(summary) between 2 and 240),
  billing_model text not null check (billing_model in ('free','flat','per_seat','contract')),
  min_seats integer check (min_seats is null or min_seats > 0),
  max_seats integer check (max_seats is null or max_seats >= min_seats),
  trial_days integer not null default 0 check (trial_days between 0 and 90),
  is_featured boolean not null default false,
  sort_order smallint not null check (sort_order > 0),
  status text not null check (status in ('draft','published','retired')),
  commercial_status text not null default 'proposed'
    check (commercial_status in ('proposed','active','retired')),
  created_at timestamptz not null default now(),
  primary key (catalog_version, plan_code),
  unique (catalog_version, sort_order),
  check (plan_code in ('free','personal','family','professional','team','business','enterprise')),
  check (
    (billing_model = 'per_seat' and min_seats is not null)
    or (billing_model <> 'per_seat' and min_seats is null and max_seats is null)
  )
);

create table public.plan_prices (
  catalog_version text not null,
  plan_code text not null,
  currency text not null check (currency in ('inr','usd')),
  billing_interval text not null check (billing_interval in ('month','year')),
  unit_amount_minor integer not null check (unit_amount_minor >= 0),
  price_scope text not null check (price_scope in ('plan','seat')),
  stripe_price_id text check (
    stripe_price_id is null or stripe_price_id ~ '^price_[A-Za-z0-9]+$'
  ),
  created_at timestamptz not null default now(),
  primary key (catalog_version, plan_code, currency, billing_interval),
  foreign key (catalog_version, plan_code)
    references public.plan_catalog(catalog_version, plan_code) on delete restrict
);

create table public.feature_catalog (
  catalog_version text not null,
  feature_key text not null check (feature_key ~ '^[a-z][a-z0-9_.-]{2,79}$'),
  display_name text not null check (length(display_name) between 2 and 120),
  description text not null check (length(description) between 2 and 300),
  category text not null check (category in ('vault','sharing','security','developer','governance','usage','enterprise')),
  security_class text not null check (security_class in ('core','convenience','governance','advanced')),
  sort_order smallint not null check (sort_order > 0),
  status text not null check (status in ('draft','published','retired')),
  created_at timestamptz not null default now(),
  primary key (catalog_version, feature_key),
  unique (catalog_version, sort_order)
);

create table public.plan_entitlements (
  catalog_version text not null,
  plan_code text not null,
  feature_key text not null,
  entitlement_value jsonb not null,
  display_text text not null check (length(display_text) between 2 and 180),
  display_order smallint not null check (display_order > 0),
  created_at timestamptz not null default now(),
  primary key (catalog_version, plan_code, feature_key),
  unique (catalog_version, plan_code, display_order),
  foreign key (catalog_version, plan_code)
    references public.plan_catalog(catalog_version, plan_code) on delete restrict,
  foreign key (catalog_version, feature_key)
    references public.feature_catalog(catalog_version, feature_key) on delete restrict
);

create index plan_entitlements_feature_idx
  on public.plan_entitlements(catalog_version, feature_key);

comment on table public.plan_catalog is
  'Public, versioned Passkey-X package metadata. Published rows are immutable and contain no customer or secret data.';
comment on table public.plan_prices is
  'Public launch-price proposals in minor currency units. A null Stripe Price ID means checkout is intentionally unavailable.';
comment on table public.feature_catalog is
  'Public feature labels and descriptions. Security controls are never weakened by plan selection.';
comment on table public.plan_entitlements is
  'Public package-to-feature mapping. Server enforcement remains authoritative in tenant_entitlements and protected operations.';

alter table public.plan_catalog enable row level security;
alter table public.plan_prices enable row level security;
alter table public.feature_catalog enable row level security;
alter table public.plan_entitlements enable row level security;

revoke all on public.plan_catalog from public, anon, authenticated;
revoke all on public.plan_prices from public, anon, authenticated;
revoke all on public.feature_catalog from public, anon, authenticated;
revoke all on public.plan_entitlements from public, anon, authenticated;
grant select on public.plan_catalog, public.plan_prices, public.feature_catalog,
  public.plan_entitlements to anon, authenticated;
grant select, insert, update, delete on public.plan_catalog, public.plan_prices,
  public.feature_catalog, public.plan_entitlements to service_role;

create policy plan_catalog_public_read
on public.plan_catalog for select to anon, authenticated
using (status = 'published');

create policy plan_prices_public_read
on public.plan_prices for select to anon, authenticated
using (exists (
  select 1 from public.plan_catalog as catalog
  where catalog.catalog_version = plan_prices.catalog_version
    and catalog.plan_code = plan_prices.plan_code
    and catalog.status = 'published'
));

create policy feature_catalog_public_read
on public.feature_catalog for select to anon, authenticated
using (status = 'published');

create policy plan_entitlements_public_read
on public.plan_entitlements for select to anon, authenticated
using (
  exists (
    select 1 from public.plan_catalog as catalog
    where catalog.catalog_version = plan_entitlements.catalog_version
      and catalog.plan_code = plan_entitlements.plan_code
      and catalog.status = 'published'
  )
  and exists (
    select 1 from public.feature_catalog as feature
    where feature.catalog_version = plan_entitlements.catalog_version
      and feature.feature_key = plan_entitlements.feature_key
      and feature.status = 'published'
  )
);

create or replace function private.prevent_published_catalog_mutation()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_status text;
begin
  if tg_table_name = 'plan_catalog' then
    v_status := old.status;
  elsif tg_table_name = 'feature_catalog' then
    v_status := old.status;
  else
    select status into v_status
    from public.plan_catalog
    where catalog_version = old.catalog_version
      and plan_code = old.plan_code;
  end if;

  if v_status = 'published' then
    raise exception 'published catalog versions are immutable' using errcode = '55000';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end
$$;

create or replace function private.prevent_published_catalog_insert()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if exists (
    select 1 from public.plan_catalog
    where catalog_version = new.catalog_version
      and plan_code = new.plan_code
      and status = 'published'
  ) then
    raise exception 'published catalog versions are immutable' using errcode = '55000';
  end if;
  return new;
end
$$;

create trigger plan_catalog_immutable
before update or delete on public.plan_catalog
for each row execute function private.prevent_published_catalog_mutation();
create trigger feature_catalog_immutable
before update or delete on public.feature_catalog
for each row execute function private.prevent_published_catalog_mutation();
create trigger plan_prices_immutable
before insert on public.plan_prices
for each row execute function private.prevent_published_catalog_insert();
create trigger plan_prices_update_immutable
before update or delete on public.plan_prices
for each row execute function private.prevent_published_catalog_mutation();
create trigger plan_entitlements_immutable
before insert on public.plan_entitlements
for each row execute function private.prevent_published_catalog_insert();
create trigger plan_entitlements_update_immutable
before update or delete on public.plan_entitlements
for each row execute function private.prevent_published_catalog_mutation();

revoke all on function private.prevent_published_catalog_mutation()
  from public, anon, authenticated;
revoke all on function private.prevent_published_catalog_insert()
  from public, anon, authenticated;

insert into public.plan_catalog(
  catalog_version, plan_code, display_name, audience, summary, billing_model,
  min_seats, max_seats, trial_days, is_featured, sort_order, status,
  commercial_status
) values
  ('2026-09-v2.2','free','Free','One person exploring Passkey-X','Core encrypted vault with privacy-safe sponsor cards.','free',null,null,0,false,10,'draft','proposed'),
  ('2026-09-v2.2','personal','Personal','Individuals','Ad-free personal protection with unlimited devices.','flat',null,null,14,false,20,'draft','proposed'),
  ('2026-09-v2.2','family','Family','Households of up to 6','Shared family vaults, recovery support, and pooled usage.','flat',null,null,14,false,30,'draft','proposed'),
  ('2026-09-v2.2','professional','Professional','Freelancers, consultants, and developers','Client workspaces and developer-secret workflows.','flat',null,null,14,false,40,'draft','proposed'),
  ('2026-09-v2.2','team','Team','Small teams and focused workgroups','Encrypted collaboration, roles, approvals, alerts, and developer tools.','per_seat',3,50,21,false,50,'draft','proposed'),
  ('2026-09-v2.2','business','Business','Growing multi-department organizations','Lifecycle governance, organization policy, and access intelligence.','per_seat',5,500,21,true,60,'draft','proposed'),
  ('2026-09-v2.2','enterprise','Enterprise','Large, regulated, and MSP organizations','Advanced trust, private deployment options, SIEM depth, and contract controls.','contract',null,null,0,false,70,'draft','proposed');

insert into public.plan_prices(
  catalog_version, plan_code, currency, billing_interval,
  unit_amount_minor, price_scope
) values
  ('2026-09-v2.2','free','inr','month',0,'plan'),
  ('2026-09-v2.2','free','usd','month',0,'plan'),
  ('2026-09-v2.2','free','inr','year',0,'plan'),
  ('2026-09-v2.2','free','usd','year',0,'plan'),
  ('2026-09-v2.2','personal','inr','month',9900,'plan'),
  ('2026-09-v2.2','personal','usd','month',199,'plan'),
  ('2026-09-v2.2','personal','inr','year',99000,'plan'),
  ('2026-09-v2.2','personal','usd','year',1990,'plan'),
  ('2026-09-v2.2','family','inr','month',24900,'plan'),
  ('2026-09-v2.2','family','usd','month',499,'plan'),
  ('2026-09-v2.2','family','inr','year',249000,'plan'),
  ('2026-09-v2.2','family','usd','year',4990,'plan'),
  ('2026-09-v2.2','professional','inr','month',19900,'plan'),
  ('2026-09-v2.2','professional','usd','month',399,'plan'),
  ('2026-09-v2.2','professional','inr','year',199000,'plan'),
  ('2026-09-v2.2','professional','usd','year',3990,'plan'),
  ('2026-09-v2.2','team','inr','month',29900,'seat'),
  ('2026-09-v2.2','team','usd','month',599,'seat'),
  ('2026-09-v2.2','team','inr','year',299000,'seat'),
  ('2026-09-v2.2','team','usd','year',5990,'seat'),
  ('2026-09-v2.2','business','inr','month',49900,'seat'),
  ('2026-09-v2.2','business','usd','month',999,'seat'),
  ('2026-09-v2.2','business','inr','year',499000,'seat'),
  ('2026-09-v2.2','business','usd','year',9990,'seat');

insert into public.feature_catalog(
  catalog_version, feature_key, display_name, description, category,
  security_class, sort_order, status
) values
  ('2026-09-v2.2','vault.encrypted','Encrypted vault','Client-side encrypted passwords, notes, passkeys, and credentials.','vault','core',10,'draft'),
  ('2026-09-v2.2','device.limit','Device access','The number or policy controlling active devices.','security','core',20,'draft'),
  ('2026-09-v2.2','sharing.verified','Verified sharing','Share encrypted data only after recipient verification.','sharing','core',30,'draft'),
  ('2026-09-v2.2','workspace.shared','Shared workspaces','Separate encrypted keys for household or organization workspaces.','sharing','core',40,'draft'),
  ('2026-09-v2.2','workspace.client','Client workspaces','Isolated project and client workspaces.','sharing','governance',50,'draft'),
  ('2026-09-v2.2','access.rbac','Roles and approvals','Role-based access, requests, approvals, and revocation.','governance','governance',60,'draft'),
  ('2026-09-v2.2','security.alerts','Security alerts','Actionable findings without disclosing vault plaintext.','security','core',70,'draft'),
  ('2026-09-v2.2','developer.tools','Developer tools','CLI, API, developer-secret, and automation foundations.','developer','advanced',80,'draft'),
  ('2026-09-v2.2','support.onboarding','Support and onboarding','Guided onboarding and product support resources.','governance','convenience',90,'draft'),
  ('2026-09-v2.2','directory.organization','Organization directory','Departments, teams, groups, and employee profiles.','governance','governance',100,'draft'),
  ('2026-09-v2.2','identity.lifecycle','Employee lifecycle','Joiner, mover, suspension, and deprovisioning controls.','governance','governance',110,'draft'),
  ('2026-09-v2.2','policy.sandbox','Policy controls','Inherited policy, simulation foundation, and enforcement.','governance','advanced',120,'draft'),
  ('2026-09-v2.2','access.graph','Access intelligence','Organization access graph and impact-analysis foundation.','governance','advanced',130,'draft'),
  ('2026-09-v2.2','identity.sso_scim','SSO and directory sync','Enterprise identity-provider and directory lifecycle integration.','enterprise','advanced',140,'draft'),
  ('2026-09-v2.2','audit.retention','Audit retention','Plan-governed audit metadata retention.','security','governance',150,'draft'),
  ('2026-09-v2.2','usage.ai','Hosted AI credits','Monthly hosted-AI allowance; vault plaintext is never sent.','usage','convenience',160,'draft'),
  ('2026-09-v2.2','usage.automation','Automation runs','Monthly completed automation allowance.','usage','convenience',170,'draft'),
  ('2026-09-v2.2','ads.sponsor','Sponsor cards','Privacy-safe first-party cards on the Free home dashboard only.','usage','convenience',180,'draft'),
  ('2026-09-v2.2','enterprise.device_trust','Advanced Device Trust','Managed posture and identity-provider enforcement.','enterprise','advanced',190,'draft'),
  ('2026-09-v2.2','enterprise.private_ai','Private AI','Contracted private model and regional processing options.','enterprise','advanced',200,'draft'),
  ('2026-09-v2.2','enterprise.siem','Advanced SIEM','Deep audit, session evidence, and SIEM integrations.','enterprise','advanced',210,'draft'),
  ('2026-09-v2.2','enterprise.ecosystem','Integration ecosystem','Contracted connector and marketplace ecosystem.','enterprise','advanced',220,'draft');

insert into public.plan_entitlements(
  catalog_version, plan_code, feature_key, entitlement_value,
  display_text, display_order
) values
  ('2026-09-v2.2','free','vault.encrypted','true','Unlimited passwords and secure notes',10),
  ('2026-09-v2.2','free','device.limit','2','2 active devices',20),
  ('2026-09-v2.2','free','sharing.verified','5','5 active verified shares',30),
  ('2026-09-v2.2','free','usage.ai','20','20 hosted AI credits each month',40),
  ('2026-09-v2.2','free','ads.sponsor','true','Privacy-safe sponsor cards on Home only',50),

  ('2026-09-v2.2','personal','vault.encrypted','true','Unlimited passwords, notes, and credentials',10),
  ('2026-09-v2.2','personal','device.limit','"unlimited"','Unlimited devices',20),
  ('2026-09-v2.2','personal','sharing.verified','"unlimited"','Unlimited verified sharing',30),
  ('2026-09-v2.2','personal','security.alerts','true','Personal security findings and alerts',40),
  ('2026-09-v2.2','personal','usage.ai','250','250 hosted AI credits each month',50),
  ('2026-09-v2.2','personal','audit.retention','"90 days"','90-day audit history',60),

  ('2026-09-v2.2','family','vault.encrypted','true','Private vaults for up to 6 family members',10),
  ('2026-09-v2.2','family','workspace.shared','true','Shared household workspaces',20),
  ('2026-09-v2.2','family','sharing.verified','"unlimited"','Verified sharing and emergency access foundation',30),
  ('2026-09-v2.2','family','device.limit','"unlimited"','Unlimited devices',40),
  ('2026-09-v2.2','family','usage.ai','800','800 pooled AI credits each month',50),
  ('2026-09-v2.2','family','audit.retention','"180 days"','180-day audit history',60),

  ('2026-09-v2.2','professional','vault.encrypted','true','Encrypted vault for one professional',10),
  ('2026-09-v2.2','professional','workspace.client','true','Client and project workspaces',20),
  ('2026-09-v2.2','professional','developer.tools','true','Developer secrets, CLI, and API starter',30),
  ('2026-09-v2.2','professional','sharing.verified','"unlimited"','Verified client handover and sharing',40),
  ('2026-09-v2.2','professional','usage.ai','1000','1,000 hosted AI credits each month',50),
  ('2026-09-v2.2','professional','audit.retention','"1 year"','1-year audit history',60),

  ('2026-09-v2.2','team','workspace.shared','true','Shared encrypted workspaces',10),
  ('2026-09-v2.2','team','access.rbac','true','Role-based access, requests, and approvals',20),
  ('2026-09-v2.2','team','sharing.verified','"unlimited"','Secure sharing with immediate revocation',30),
  ('2026-09-v2.2','team','security.alerts','true','Actionable team security alerts',40),
  ('2026-09-v2.2','team','developer.tools','true','Developer tools and automation starter',50),
  ('2026-09-v2.2','team','support.onboarding','true','Guided onboarding resources',60),
  ('2026-09-v2.2','team','usage.ai','"600/user"','600 hosted AI credits per user each month',70),
  ('2026-09-v2.2','team','audit.retention','"1 year"','1-year audit history',80),

  ('2026-09-v2.2','business','workspace.shared','true','Everything in Team',10),
  ('2026-09-v2.2','business','directory.organization','true','Departments, teams, groups, and directory',20),
  ('2026-09-v2.2','business','identity.lifecycle','true','Joiner, mover, suspension, and offboarding controls',30),
  ('2026-09-v2.2','business','access.rbac','true','Delegated roles and vault permissions',40),
  ('2026-09-v2.2','business','access.graph','"organization"','Organization access intelligence',50),
  ('2026-09-v2.2','business','policy.sandbox','true','Inherited policy and simulation foundation',60),
  ('2026-09-v2.2','business','identity.sso_scim','"add-on"','SSO and directory integrations as an add-on',70),
  ('2026-09-v2.2','business','security.alerts','true','Organization-wide security hygiene alerts',80),
  ('2026-09-v2.2','business','usage.ai','"2000/user"','2,000 hosted AI credits per user each month',90),
  ('2026-09-v2.2','business','audit.retention','"3 years"','3-year audit history',100),

  ('2026-09-v2.2','enterprise','enterprise.device_trust','true','Advanced Device Trust and IdP enforcement',10),
  ('2026-09-v2.2','enterprise','identity.sso_scim','true','Federated SSO and directory lifecycle',20),
  ('2026-09-v2.2','enterprise','enterprise.private_ai','true','Private AI and contracted data regions',30),
  ('2026-09-v2.2','enterprise','enterprise.siem','true','Advanced SIEM and session evidence',40),
  ('2026-09-v2.2','enterprise','enterprise.ecosystem','"contract"','Contracted connector ecosystem',50),
  ('2026-09-v2.2','enterprise','access.graph','"federated"','Federated access graph and governance',60),
  ('2026-09-v2.2','enterprise','audit.retention','"policy"','Policy and contract-based retention',70);

update public.feature_catalog
set status = 'published'
where catalog_version = '2026-09-v2.2';

update public.plan_catalog
set status = 'published'
where catalog_version = '2026-09-v2.2';

commit;
