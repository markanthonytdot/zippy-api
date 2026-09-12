-- One workflow per existing Partner Access identity and platform. No duplicate email/OTP storage.
create table tester_invitations (
  id uuid primary key,
  person_id uuid not null references partner_people(id) on delete cascade,
  platform text not null check (platform in ('ios','android')),
  platform_status text not null default 'pending' check (platform_status in ('pending','failed','confirmed')),
  provider_state text,
  provider_tester_id text,
  platform_confirmed_at timestamptz,
  email_status text not null default 'not_sent' check (email_status in ('not_sent','sending','failed','sent')),
  email_key uuid,
  email_payload jsonb,
  email_started_at timestamptz,
  email_sent_at timestamptz,
  email_message_id text,
  apple_resend_at timestamptz,
  error_code text,
  last_attempt_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(person_id, platform)
);
create index tester_invitations_updated_idx on tester_invitations(updated_at desc);
