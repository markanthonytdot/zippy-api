-- A new survey has its own table. No historical row, table or ledger is rewritten.
create table combined_demo_feedback_responses (
  id uuid primary key,
  request_id uuid not null unique,
  survey_version text not null check (survey_version = 'combined_demo_v3'),
  clarity text not null check (clarity in ('Very clear', 'Somewhat clear', 'Not very clear', 'Not clear at all')),
  use_likelihood text not null check (use_likelihood in ('Definitely', 'Probably', 'Probably not', 'Definitely not')),
  booked_travel_last_12_months boolean not null,
  source text not null default 'direct' check (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  submitted_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index combined_demo_feedback_submitted_idx on combined_demo_feedback_responses (submitted_at desc, id);
create index combined_demo_feedback_source_idx on combined_demo_feedback_responses (source, submitted_at desc);
revoke all on combined_demo_feedback_responses from public;
