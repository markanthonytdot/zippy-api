create table if not exists hotel_booking_sessions (
  id uuid primary key,
  user_id text not null,
  checkout_fingerprint text not null,
  duffel_rate_id text not null,
  duffel_quote_id text not null,
  quote_snapshot jsonb not null,
  hotel_snapshot jsonb not null,
  room_snapshot jsonb not null,
  search_snapshot jsonb not null,
  guest_info jsonb,
  contact_info jsonb,
  provider_currency text not null,
  provider_total_minor bigint not null,
  customer_currency text not null,
  customer_total_minor bigint not null,
  fx_rate numeric,
  fx_source text,
  stripe_payment_intent_id text unique,
  stripe_payment_status text not null default 'not_created',
  stripe_payment_last_event_created bigint not null default 0,
  stripe_payment_last_event_precedence integer not null default 0,
  stripe_payment_last_event_id text,
  booking_status text not null default 'guest_details_required',
  duffel_booking_id text unique,
  duffel_booking_reference text,
  duffel_request_id text,
  duffel_post_started_at timestamptz,
  booking_claim_token uuid,
  booking_claim_expires_at timestamptz,
  confirmation_snapshot jsonb,
  recovery_status text,
  stripe_refund_id text,
  stripe_refund_last_event_created bigint not null default 0,
  stripe_refund_last_event_precedence integer not null default 0,
  stripe_refund_last_event_id text,
  failure_code text,
  failure_message text,
  confirmed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (booking_status in (
    'guest_details_required', 'payment_setup', 'awaiting_payment', 'payment_paid',
    'booking_in_progress', 'booking_unknown', 'booking_failed_refunded',
    'booking_failed_refund_pending', 'payment_canceled', 'confirmed'
  ))
);

create index if not exists idx_hotel_booking_sessions_user_created
  on hotel_booking_sessions(user_id, created_at desc);

create index if not exists idx_hotel_booking_sessions_status
  on hotel_booking_sessions(booking_status, updated_at);

create index if not exists idx_hotel_booking_sessions_fingerprint
  on hotel_booking_sessions(user_id, checkout_fingerprint);

create table if not exists hotel_booking_recovery_jobs (
  booking_session_id uuid not null references hotel_booking_sessions(id) on delete cascade,
  kind text not null check (kind in ('stuck_claim', 'duffel_reconcile', 'refund_reconcile')),
  status text not null default 'queued' check (status in ('queued', 'claimed', 'completed', 'manual_review')),
  available_at timestamptz not null default now(),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  claim_token uuid,
  claimed_by text,
  claim_expires_at timestamptz,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((status = 'claimed') =
    (claim_token is not null and claimed_by is not null and claim_expires_at is not null)),
  primary key (booking_session_id, kind)
);

create index if not exists idx_hotel_booking_recovery_jobs_due
  on hotel_booking_recovery_jobs(status, available_at, claim_expires_at);
