-- Package research is separate from the existing flight answers and metrics.
create table package_feedback_responses (
  id uuid primary key,
  request_id uuid not null unique,
  demo_type text not null default 'package' check (demo_type = 'package'),
  likelihood text not null check (likelihood in ('Definitely', 'Probably', 'Probably not', 'Definitely not')),
  usefulness text not null check (usefulness in ('Yes', 'No', 'Not sure')),
  comment text not null default '' check (char_length(comment) <= 2000),
  source text not null default 'direct' check (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  entry_path text not null default 'direct' check (entry_path in ('direct', 'flight_thank_you')),
  submitted_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index package_feedback_submitted_idx on package_feedback_responses (submitted_at desc, id);
create index package_feedback_source_idx on package_feedback_responses (source, submitted_at desc);
create index package_feedback_entry_idx on package_feedback_responses (entry_path, submitted_at desc);

-- An event UUID deduplicates retries of one CTA. It is not a visitor identifier,
-- is not shared with package responses, and has no link to a flight response.
create table package_feedback_clicks (
  event_id uuid primary key,
  event_type text not null default 'flight_thank_you_click' check (event_type = 'flight_thank_you_click'),
  source text not null default 'direct' check (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  created_at timestamptz not null default now()
);
create index package_feedback_click_source_idx on package_feedback_clicks (source, created_at desc);
create index package_feedback_click_created_idx on package_feedback_clicks (created_at desc);

-- Window-specific HMACs only; no raw IPs or response/event foreign keys.
create table package_feedback_rate_limits (
  bucket_key text primary key,
  count integer not null,
  expires_at timestamptz not null
);
create index package_feedback_rate_expiry_idx on package_feedback_rate_limits (expires_at);
revoke all on package_feedback_responses, package_feedback_clicks, package_feedback_rate_limits from public;
