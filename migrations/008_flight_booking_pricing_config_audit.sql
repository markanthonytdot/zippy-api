alter table pricing_configurations
  add column if not exists based_on_version bigint;

alter table flight_booking_sessions
  add column if not exists pricing_config_source text,
  add column if not exists pricing_config_version bigint,
  add column if not exists pricing_config_snapshot jsonb;

create index if not exists idx_flight_booking_sessions_pricing_config
  on flight_booking_sessions(pricing_config_version, created_at desc);
