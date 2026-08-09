alter table flight_booking_sessions
  add column if not exists booking_mode text not null default 'test',
  add column if not exists stripe_charge_id text,
  add column if not exists stripe_balance_transaction_id text,
  add column if not exists stripe_actual_processing_minor bigint,
  add column if not exists stripe_actual_processing_currency text,
  add column if not exists stripe_fee_reconciled_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'flight_booking_sessions_booking_mode_check'
      and conrelid = 'flight_booking_sessions'::regclass
  ) then
    alter table flight_booking_sessions
      add constraint flight_booking_sessions_booking_mode_check
      check (booking_mode in ('test', 'live'));
  end if;
end $$;

create index if not exists idx_flight_booking_sessions_user_recovery
  on flight_booking_sessions(user_id, booking_status, updated_at desc);
