begin;

insert into auth.users(id,instance_id,aud,role,email,email_confirmed_at,encrypted_password,created_at,updated_at)
values ('54000000-0000-4000-8000-000000000004','00000000-0000-0000-0000-000000000000','authenticated','authenticated','sms-observability@example.invalid',now(),'',now(),now());

insert into public.auth_sms_deliveries(
  id, auth_hook_id, auth_user_id, payload_sha256, provider_message_id, provider_status
) values (
  '64000000-0000-4000-8000-000000000004', 'hook_phase0_5_sms_test',
  '54000000-0000-4000-8000-000000000004', decode(repeat('11',32),'hex'),
  'message_phase0_5_sms_test', 'accepted'
);

do $$
begin
  if not public.apply_sent_sms_delivery_event(
    'message_phase0_5_sms_test','message.delivered','DELIVERED','sms',
    '2026-09-05T08:30:00Z',decode(repeat('22',32),'hex')
  ) then raise exception 'first verified event was not applied'; end if;

  if public.apply_sent_sms_delivery_event(
    'message_phase0_5_sms_test','message.delivered','DELIVERED','sms',
    '2026-09-05T08:30:00Z',decode(repeat('22',32),'hex')
  ) then raise exception 'duplicate verified event was applied twice'; end if;

  if public.apply_sent_sms_delivery_event(
    'unrelated_message_identifier','message.delivered','DELIVERED','sms',
    '2026-09-05T08:30:00Z',decode(repeat('33',32),'hex')
  ) then raise exception 'unrelated Sent event was persisted'; end if;

  if (select count(*) from public.auth_sms_delivery_events where provider_message_id='message_phase0_5_sms_test') <> 1 then
    raise exception 'unexpected SMS event count';
  end if;
  if (select provider_status from public.auth_sms_deliveries where id='64000000-0000-4000-8000-000000000004') <> 'DELIVERED' then
    raise exception 'delivery projection did not advance';
  end if;
end
$$;

set local role authenticated;
select set_config('request.jwt.claim.sub','54000000-0000-4000-8000-000000000004',true);

do $$
begin
  perform * from public.auth_sms_deliveries;
  raise exception 'browser role read backend-only SMS delivery data';
exception when insufficient_privilege then null;
end
$$;

do $$
begin
  perform public.apply_sent_sms_delivery_event(
    'message_phase0_5_sms_test','message.sent','SENT','sms',now(),decode(repeat('44',32),'hex')
  );
  raise exception 'browser role executed the SMS event projector';
exception when insufficient_privilege then null;
end
$$;

reset role;
rollback;
