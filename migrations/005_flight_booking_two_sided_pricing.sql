alter table flight_booking_sessions
  add column if not exists provider_currency text,
  add column if not exists provider_offer_minor bigint,
  add column if not exists provider_services_minor bigint not null default 0,
  add column if not exists provider_total_minor bigint,
  add column if not exists customer_currency text,
  add column if not exists customer_fx_rate numeric(20,10),
  add column if not exists customer_fx_source text,
  add column if not exists customer_fx_margin_bps integer,
  add column if not exists customer_base_fare_minor bigint,
  add column if not exists customer_taxes_minor bigint,
  add column if not exists customer_services_minor bigint not null default 0,
  add column if not exists customer_converted_minor bigint,
  add column if not exists customer_zippi_fee_minor bigint,
  add column if not exists customer_pre_round_minor bigint,
  add column if not exists customer_rounding_increment_minor bigint,
  add column if not exists customer_rounding_adjustment_minor bigint,
  add column if not exists customer_total_minor bigint;

update flight_booking_sessions
set provider_currency = coalesce(provider_currency, currency),
    provider_offer_minor = coalesce(provider_offer_minor, offer_minor),
    provider_services_minor = coalesce(provider_services_minor, services_minor),
    provider_total_minor = coalesce(provider_total_minor, duffel_total_minor),
    customer_currency = coalesce(customer_currency, currency),
    customer_zippi_fee_minor = coalesce(customer_zippi_fee_minor, zippi_fee_minor),
    customer_total_minor = coalesce(customer_total_minor, charge_total_minor)
where provider_currency is null
   or provider_offer_minor is null
   or provider_total_minor is null
   or customer_currency is null
   or customer_zippi_fee_minor is null
   or customer_total_minor is null;
