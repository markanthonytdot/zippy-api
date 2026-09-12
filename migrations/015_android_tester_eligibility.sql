-- Production-only Android delivery state. No staging OTP/session data is imported.
alter table tester_invitations
  add column play_eligibility text not null default 'not_confirmed'
    check (play_eligibility in ('not_confirmed', 'confirmed', 'removed')),
  add column play_eligibility_at timestamptz,
  add column play_eligibility_actor text;

-- A server-owned default organization; no tester accounts or credentials are seeded.
insert into partner_organizations(id, name)
values ('d64dfe7a-3058-4e43-9283-182f60b08baa', 'Android Internal Testers');
