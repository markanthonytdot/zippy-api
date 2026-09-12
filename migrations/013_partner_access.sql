-- Explicit invitations; domains are an additional restriction, never authorization.
create table partner_organizations (
  id uuid primary key,
  name text not null,
  status text not null default 'active' check (status in ('active', 'disabled')),
  allowed_email_domains jsonb not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table partner_people (
  id uuid primary key,
  email text not null unique check (email = lower(btrim(email))),
  organization_id uuid not null references partner_organizations(id),
  status text not null default 'active' check (status in ('active', 'disabled')),
  starts_at timestamptz not null,
  expires_at timestamptz not null check (expires_at > starts_at),
  revoked_at timestamptz,
  platforms jsonb not null default '["ios", "android"]',
  features jsonb not null default '{"flights":true,"hotels":true,"combinedTrip":true,"checkout":false}',
  activated_at timestamptz,
  last_checked_at timestamptz,
  last_active_at timestamptz,
  expiry_audited_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table partner_verifications (
  id uuid primary key,
  person_id uuid not null references partner_people(id) on delete cascade,
  code_digest text not null,
  platform text not null check (platform in ('ios','android')),
  expires_at timestamptz not null,
  attempts integer not null default 0,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
create index partner_verifications_person_created on partner_verifications(person_id, created_at desc);
create table partner_access_audit (
  id bigint generated always as identity primary key,
  person_id uuid references partner_people(id) on delete set null,
  organization_id uuid references partner_organizations(id),
  event text not null,
  actor text not null,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index partner_access_audit_person_created on partner_access_audit(person_id, created_at desc);
-- HMAC keys contain no email, device identifier or raw IP. Durable across workers.
create table partner_access_rate_limits (
  bucket_key text primary key,
  count integer not null,
  expires_at timestamptz not null
);
