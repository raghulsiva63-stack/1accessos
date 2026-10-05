-- Security emails can go out through ZeptoMail (security-notify, ZEPTOMAIL_TOKEN).
alter table public.notification_deliveries drop constraint if exists notification_deliveries_provider_check;
alter table public.notification_deliveries add constraint notification_deliveries_provider_check
  check (provider in ('supabase','sent','smtp','resend','zeptomail'));
