-- Anonymous demo research. Only the shared API's database role accesses these tables.
create table demo_feedback_responses (
  id uuid primary key,
  request_id uuid not null unique,
  understanding text not null check (char_length(btrim(understanding)) between 1 and 2000),
  likelihood text not null check (likelihood in ('Definitely', 'Probably', 'Probably not', 'Definitely not')),
  reason text not null default '' check (char_length(reason) <= 2000),
  recent_flight_shopper boolean not null,
  source text not null default 'direct' check (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  submitted_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index demo_feedback_submitted_idx on demo_feedback_responses (submitted_at desc, id);
create index demo_feedback_source_idx on demo_feedback_responses (source, submitted_at desc);

-- HMAC buckets contain no raw IPs and cannot be joined to responses.
create table demo_feedback_rate_limits (
  bucket_key text primary key,
  count integer not null,
  expires_at timestamptz not null
);
create index demo_feedback_rate_expiry_idx on demo_feedback_rate_limits (expires_at);
revoke all on demo_feedback_responses, demo_feedback_rate_limits from public;
