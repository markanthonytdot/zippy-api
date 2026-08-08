create table if not exists flight_booking_sessions (
  id uuid primary key,
  user_id text not null,
  checkout_fingerprint text not null,
  duffel_offer_id text not null,
  offer_snapshot jsonb not null,
  payload_snapshot jsonb not null,
  traveler_info jsonb not null,
  contact_info jsonb not null,
  selected_services jsonb not null default '[]'::jsonb,
  currency text not null,
  offer_minor bigint not null,
  services_minor bigint not null default 0,
  duffel_total_minor bigint not null,
  zippi_fee_minor bigint not null default 0,
  charge_total_minor bigint not null,
  stripe_payment_intent_id text unique,
  stripe_payment_status text not null default 'not_created',
  booking_status text not null default 'payment_setup',
  duffel_order_id text unique,
  duffel_booking_reference text,
  duffel_request_id text,
  confirmation_snapshot jsonb,
  recovery_status text,
  stripe_refund_id text,
  failure_code text,
  failure_message text,
  duffel_attempted_at timestamptz,
  confirmed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (booking_status in (
    'payment_setup', 'awaiting_payment', 'payment_paid', 'booking_in_progress',
    'booking_unknown', 'booking_failed_refunded', 'booking_failed_refund_pending', 'confirmed'
  ))
);

create index if not exists idx_flight_booking_sessions_user_created
  on flight_booking_sessions(user_id, created_at desc);

create index if not exists idx_flight_booking_sessions_status
  on flight_booking_sessions(booking_status, updated_at);

create index if not exists idx_flight_booking_sessions_fingerprint
  on flight_booking_sessions(user_id, checkout_fingerprint);
