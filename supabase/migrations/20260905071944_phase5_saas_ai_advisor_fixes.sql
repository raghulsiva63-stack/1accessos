begin;

create index connector_credentials_tenant_connector_fk_idx on public.connector_credentials(tenant_id,connector_id);
create index lifecycle_workflow_runs_tenant_workflow_fk_idx on public.lifecycle_workflow_runs(tenant_id,workflow_id);
create index msp_tenant_access_approved_by_fk_idx on public.msp_tenant_access(approved_by) where approved_by is not null;
create index msp_tenant_access_created_by_fk_idx on public.msp_tenant_access(created_by);
create index saas_applications_tenant_connector_fk_idx on public.saas_applications(tenant_id,connector_id) where connector_id is not null;
create index saas_licenses_tenant_account_fk_idx on public.saas_licenses(tenant_id,account_id) where account_id is not null;
create index saas_recommendations_tenant_application_fk_idx on public.saas_recommendations(tenant_id,application_id) where application_id is not null;
create index saas_savings_tenant_application_fk_idx on public.saas_savings_ledger(tenant_id,application_id) where application_id is not null;
create index saas_savings_tenant_recommendation_fk_idx on public.saas_savings_ledger(tenant_id,recommendation_id) where recommendation_id is not null;
create index saas_usage_facts_identity_fk_idx on public.saas_usage_facts(identity_id) where identity_id is not null;
create index tenant_connectors_catalog_fk_idx on public.tenant_connectors(connector_key);

drop policy tenant_connectors_manage on public.tenant_connectors;
create policy tenant_connectors_insert on public.tenant_connectors for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy tenant_connectors_update on public.tenant_connectors for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy tenant_connectors_delete on public.tenant_connectors for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_applications_manage on public.saas_applications;
create policy saas_applications_insert on public.saas_applications for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_applications_update on public.saas_applications for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_applications_delete on public.saas_applications for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_identity_accounts_manage on public.saas_identity_accounts;
create policy saas_identity_accounts_insert on public.saas_identity_accounts for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_identity_accounts_update on public.saas_identity_accounts for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_identity_accounts_delete on public.saas_identity_accounts for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_contracts_manage on public.saas_contracts;
create policy saas_contracts_insert on public.saas_contracts for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_contracts_update on public.saas_contracts for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_contracts_delete on public.saas_contracts for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_licenses_manage on public.saas_licenses;
create policy saas_licenses_insert on public.saas_licenses for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_licenses_update on public.saas_licenses for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_licenses_delete on public.saas_licenses for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy spend_budgets_manage on public.spend_budgets;
create policy spend_budgets_insert on public.spend_budgets for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy spend_budgets_update on public.spend_budgets for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy spend_budgets_delete on public.spend_budgets for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_recommendations_manage on public.saas_recommendations;
create policy saas_recommendations_insert on public.saas_recommendations for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_recommendations_update on public.saas_recommendations for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_recommendations_delete on public.saas_recommendations for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy lifecycle_workflows_manage on public.lifecycle_workflows;
create policy lifecycle_workflows_insert on public.lifecycle_workflows for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy lifecycle_workflows_update on public.lifecycle_workflows for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy lifecycle_workflows_delete on public.lifecycle_workflows for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy lifecycle_workflow_runs_manage on public.lifecycle_workflow_runs;
create policy lifecycle_workflow_runs_insert on public.lifecycle_workflow_runs for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy lifecycle_workflow_runs_update on public.lifecycle_workflow_runs for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy lifecycle_workflow_runs_delete on public.lifecycle_workflow_runs for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

drop policy saas_savings_ledger_manage on public.saas_savings_ledger;
create policy saas_savings_ledger_insert on public.saas_savings_ledger for insert to authenticated with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_savings_ledger_update on public.saas_savings_ledger for update to authenticated using ((select private.can_manage_phase5_tenant(tenant_id))) with check ((select private.can_manage_phase5_tenant(tenant_id)));
create policy saas_savings_ledger_delete on public.saas_savings_ledger for delete to authenticated using ((select private.can_manage_phase5_tenant(tenant_id)));

create or replace function public.refresh_saas_recommendations(p_tenant_id uuid)
returns integer language plpgsql security invoker set search_path = ''
as $$
declare v_count integer := 0; v_rows integer := 0;
begin
  if not private.has_business_entitlement(p_tenant_id)
    or not private.can_manage_phase5_tenant(p_tenant_id) then
    raise exception 'SaaS manager permission required' using errcode = '42501';
  end if;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,
    estimated_savings_minor,currency,evidence,destructive_action
  )
  select contract.tenant_id,contract.application_id,
    'unused-seats:' || contract.id::text || ':' || current_date::text,
    'unused_seats','medium','Review unused ' || app.display_name || ' seats',
    (contract.purchased_seats - count(license.id))::text || ' purchased seats are currently unassigned.',
    (contract.purchased_seats - count(license.id)) * contract.unit_cost_minor,
    contract.currency,
    jsonb_build_object('contract_id',contract.id,'purchased',contract.purchased_seats,'assigned',count(license.id),'source','license_inventory'),
    true
  from public.saas_contracts contract
  join public.saas_applications app on app.tenant_id = contract.tenant_id and app.id = contract.application_id
  left join public.saas_licenses license on license.tenant_id = contract.tenant_id
    and license.contract_id = contract.id and license.status in ('assigned','suspended')
  where contract.tenant_id = p_tenant_id
  group by contract.id,app.display_name
  having contract.purchased_seats > count(license.id)
  on conflict (tenant_id,recommendation_key) do update set
    explanation = excluded.explanation,estimated_savings_minor = excluded.estimated_savings_minor,
    currency = excluded.currency,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select account.tenant_id,account.application_id,'ghost:' || account.id::text,
    'ghost_account',case when account.privilege_tier in ('admin','privileged') then 'high' else 'medium' end,
    'Review unmatched ' || app.display_name || ' account',
    'The account has no confirmed active owner. Reconcile identity evidence before changing access.',
    jsonb_build_object('account_id',account.id,'owner_state',account.owner_state,'privilege_tier',account.privilege_tier,'source','approved_connector_metadata')
  from public.saas_identity_accounts account
  join public.saas_applications app on app.tenant_id = account.tenant_id and app.id = account.application_id
  where account.tenant_id = p_tenant_id and account.owner_state in ('unmatched','departed')
    and account.account_status = 'active'
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity,explanation = excluded.explanation,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;

  insert into public.saas_recommendations(tenant_id,recommendation_key,kind,severity,title,explanation,evidence)
  select app.tenant_id,'duplicate:' || app.category || ':' || current_date::text,
    'duplicate_tool','low','Review overlapping ' || app.category || ' tools',
    count(*)::text || ' applications share this category. Confirm whether their use cases or contracts overlap before consolidation.',
    jsonb_build_object('category',app.category,'application_count',count(*),'application_ids',jsonb_agg(app.id order by app.id))
  from public.saas_applications app
  where app.tenant_id = p_tenant_id and app.sanctioned_state <> 'blocked'
  group by app.tenant_id,app.category having count(*) > 1
  on conflict (tenant_id,recommendation_key) do update set
    explanation = excluded.explanation,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select license.tenant_id,contract.application_id,'identity-drift:' || license.id::text,
    'identity_drift','high','Review license assigned to an inactive identity',
    'The assigned identity or tenant membership is no longer active. Review the grant before reclaiming the license.',
    jsonb_build_object('license_id',license.id,'identity_id',license.assigned_identity_id,'identity_status',identity.status,'membership_status',membership.status)
  from public.saas_licenses license
  join public.saas_contracts contract on contract.tenant_id = license.tenant_id and contract.id = license.contract_id
  join public.identities identity on identity.id = license.assigned_identity_id
  left join public.tenant_memberships membership on membership.tenant_id = license.tenant_id and membership.identity_id = license.assigned_identity_id
  where license.tenant_id = p_tenant_id and license.status in ('assigned','suspended')
    and (identity.status <> 'active' or membership.status is distinct from 'active')
  on conflict (tenant_id,recommendation_key) do update set
    explanation = excluded.explanation,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;

  insert into public.saas_recommendations(
    tenant_id,application_id,recommendation_key,kind,severity,title,explanation,evidence
  )
  select contract.tenant_id,contract.application_id,
    'renewal:' || contract.id::text || ':' || contract.renewal_at::text,
    'renewal',case when contract.renewal_at <= current_date + 30 then 'high' else 'medium' end,
    app.display_name || ' renewal needs review',
    'Renewal is due on ' || contract.renewal_at::text || '. Confirm ownership, usage, notice period, and commercial terms.',
    jsonb_build_object('contract_id',contract.id,'renewal_at',contract.renewal_at,'notice_days',contract.notice_days)
  from public.saas_contracts contract
  join public.saas_applications app on app.tenant_id = contract.tenant_id and app.id = contract.application_id
  where contract.tenant_id = p_tenant_id and contract.renewal_at between current_date and current_date + 90
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity,explanation = excluded.explanation,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;

  insert into public.saas_recommendations(tenant_id,recommendation_key,kind,severity,title,explanation,evidence)
  select budget.tenant_id,'budget:' || budget.id::text || ':' || budget.period_start::text,
    'budget_anomaly',case when budget.consumed >= budget.hard_limit then 'critical' else 'high' end,
    'Spend budget threshold reached',
    'Usage reached ' || budget.consumed::text || ' of the ' || budget.hard_limit::text || ' hard limit. Enforcement is ' || budget.enforcement || '.',
    jsonb_build_object('budget_id',budget.id,'metric',budget.metric,'consumed',budget.consumed,'soft_limit',budget.soft_limit,'hard_limit',budget.hard_limit,'enforcement',budget.enforcement)
  from public.spend_budgets budget
  where budget.tenant_id = p_tenant_id and current_date between budget.period_start and budget.period_end
    and budget.consumed >= budget.soft_limit
  on conflict (tenant_id,recommendation_key) do update set
    severity = excluded.severity,explanation = excluded.explanation,evidence = excluded.evidence,generated_at = now();
  get diagnostics v_rows = row_count; v_count := v_count + v_rows;
  return v_count;
end
$$;

comment on function public.refresh_saas_recommendations(uuid) is
  'Proposal-only unused-seat, ghost-account, identity-drift, duplicate-tool, renewal and budget analysis.';

commit;
