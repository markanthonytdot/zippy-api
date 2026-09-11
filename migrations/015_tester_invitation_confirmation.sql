alter table tester_invitations
  add column confirmation_pending_since timestamptz,
  add column confirmation_next_check_at timestamptz,
  add column confirmation_checks integer not null default 0,
  add column provider_metadata jsonb not null default '[]'::jsonb;

-- Old pending failures are reconciled by lookup, never by resending or recreating.
update tester_invitations
set platform_status='pending', confirmation_pending_since=coalesce(last_attempt_at,updated_at),
    confirmation_next_check_at=now()
where platform='ios' and error_code='apple_invitation_pending';
create index tester_invitation_confirmation_due_idx on tester_invitations(confirmation_next_check_at)
  where confirmation_next_check_at is not null;
