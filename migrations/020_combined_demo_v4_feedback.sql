-- V4 has separate storage so every earlier answer retains its original meaning.
create table combined_demo_v4_feedback_responses (
  id uuid primary key,
  request_id uuid not null unique,
  survey_version text not null check (survey_version = 'combined_demo_v4'),
  clarity text not null check (clarity in ('Very clear', 'Somewhat clear', 'Not very clear', 'Not clear at all')),
  use_likelihood text not null check (use_likelihood in ('Definitely', 'Probably', 'Probably not', 'Definitely not')),
  booked_travel_last_12_months boolean not null,
  source text not null default 'direct' check (source ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
  submitted_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index combined_demo_v4_feedback_submitted_idx on combined_demo_v4_feedback_responses (submitted_at desc, id);
create index combined_demo_v4_feedback_source_idx on combined_demo_v4_feedback_responses (source, submitted_at desc);

-- At most one optional comment belongs to the same structured response ID.
-- Omitted or blank comments have no row; both records are written atomically.
create table combined_demo_v4_feedback_comments (
  response_id uuid primary key references combined_demo_v4_feedback_responses(id),
  comment text not null check (char_length(comment) between 1 and 2000 and char_length(btrim(comment, E' \t\r\n')) > 0),
  created_at timestamptz not null default now()
);
revoke all on combined_demo_v4_feedback_responses, combined_demo_v4_feedback_comments from public;
