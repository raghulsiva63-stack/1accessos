begin;

-- The signed Stripe webhook invokes a SECURITY INVOKER transaction as
-- service_role. Schema USAGE is required in addition to the table-level SELECT
-- grant; no browser role receives access to the private catalog policy.
grant usage on schema private to service_role;
grant select on private.billing_plan_policies to service_role;

commit;
