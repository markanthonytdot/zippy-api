alter table flight_booking_sessions
  add column if not exists stripe_payment_last_event_created bigint not null default 0;

alter table flight_booking_sessions
  add column if not exists stripe_refund_last_event_created bigint not null default 0;

alter table flight_booking_sessions
  add column if not exists stripe_payment_last_event_precedence integer not null default 0;

alter table flight_booking_sessions
  add column if not exists stripe_payment_last_event_id text;

alter table flight_booking_sessions
  add column if not exists stripe_refund_last_event_precedence integer not null default 0;

alter table flight_booking_sessions
  add column if not exists stripe_refund_last_event_id text;

alter table flight_booking_sessions
  add column if not exists booking_claim_token uuid;

alter table flight_booking_sessions
  add column if not exists booking_claim_expires_at timestamptz;

create table if not exists flight_booking_recovery_jobs (
  booking_session_id uuid not null references flight_booking_sessions(id) on delete cascade,
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

create index if not exists idx_flight_booking_recovery_jobs_due
  on flight_booking_recovery_jobs(status, available_at, claim_expires_at);

create table if not exists stripe_webhook_events (
  event_id text primary key,
  event_type text not null,
  object_id text,
  booking_session_id uuid,
  event_created bigint not null,
  normalized_payload jsonb not null default '{}'::jsonb,
  processing_result text,
  received_at timestamptz not null default now(),
  processed_at timestamptz
);

create index if not exists idx_stripe_webhook_events_session
  on stripe_webhook_events(booking_session_id, received_at desc);
