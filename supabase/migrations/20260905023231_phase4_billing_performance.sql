begin;

-- Cover the composite customer-mode foreign key used by subscription cleanup
-- and integrity checks. The tenant primary key alone does not satisfy the
-- database advisor's composite-index requirement.
create index billing_subscriptions_tenant_mode_idx
  on public.billing_subscriptions(tenant_id, livemode);

commit;
