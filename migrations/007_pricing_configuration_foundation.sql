create table if not exists pricing_configurations (
  id uuid primary key default gen_random_uuid(),
  product text not null,
  environment text not null,
  version bigint not null,
  status text not null default 'draft',
  config jsonb not null,
  created_by text,
  created_at timestamptz not null default now(),
  activated_by text,
  activated_at timestamptz,
  archived_at timestamptz,
  check (product in ('flights', 'hotels')),
  check (environment in ('test', 'production')),
  check (status in ('draft', 'active', 'archived')),
  unique (product, environment, version)
);

create unique index if not exists idx_pricing_configurations_one_active
  on pricing_configurations(product, environment)
  where status = 'active';

create index if not exists idx_pricing_configurations_history
  on pricing_configurations(product, environment, created_at desc);
