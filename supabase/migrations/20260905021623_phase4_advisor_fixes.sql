begin;

-- Server-only billing tables have no browser grants. Explicit deny policies
-- document that boundary and keep the Supabase advisor baseline unambiguous.
create policy billing_customers_deny_clients
on public.billing_customers for all to anon, authenticated
using (false) with check (false);

create policy billing_subscriptions_deny_clients
on public.billing_subscriptions for all to anon, authenticated
using (false) with check (false);

create policy billing_events_deny_clients
on public.billing_events for all to anon, authenticated
using (false) with check (false);

commit;

