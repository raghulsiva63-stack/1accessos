begin;

do $$
begin
  if (select count(*) from public.plan_catalog
      where catalog_version = '2026-09-v2.2' and status = 'published') <> 7 then
    raise exception 'Phase 6 catalog does not contain seven published plans';
  end if;
  if (select count(*) from public.plan_prices
      where catalog_version = '2026-09-v2.2') <> 24 then
    raise exception 'Phase 6 catalog price count mismatch';
  end if;
  if (select count(*) from public.plan_entitlements
      where catalog_version = '2026-09-v2.2') <> 48 then
    raise exception 'Phase 6 catalog entitlement count mismatch';
  end if;
  if exists (select 1 from public.plan_prices where stripe_price_id is not null) then
    raise exception 'Unapproved Stripe Price mapping found';
  end if;
end
$$;

set local role anon;

do $$
begin
  if (select count(*) from public.plan_catalog) <> 7 then
    raise exception 'Anonymous catalog read did not return published plans only';
  end if;
  begin
    insert into public.plan_catalog(
      catalog_version, plan_code, display_name, audience, summary,
      billing_model, trial_days, sort_order, status
    ) values (
      'unauthorized', 'free', 'Bad plan', 'Bad audience', 'Unauthorized insert',
      'free', 0, 1, 'draft'
    );
    raise exception 'Anonymous catalog insert unexpectedly succeeded';
  exception when insufficient_privilege then
    null;
  end;
end
$$;

reset role;

do $$
begin
  begin
    update public.plan_catalog
      set display_name = 'Mutated'
      where catalog_version = '2026-09-v2.2' and plan_code = 'team';
    raise exception 'Published catalog mutation unexpectedly succeeded';
  exception when sqlstate '55000' then
    null;
  end;
end
$$;

rollback;
