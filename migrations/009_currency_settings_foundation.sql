alter table pricing_configurations
  drop constraint if exists pricing_configurations_product_check;

alter table pricing_configurations
  add constraint pricing_configurations_product_check
  check (product in ('flights', 'hotels', 'currencies'));
