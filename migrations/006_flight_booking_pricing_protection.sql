alter table flight_booking_sessions
  add column if not exists customer_raw_converted_minor bigint,
  add column if not exists customer_fx_protection_minor bigint,
  add column if not exists customer_zippi_markup_bps integer,
  add column if not exists customer_zippi_markup_minor bigint,
  add column if not exists customer_payment_processing_percent_bps integer,
  add column if not exists customer_payment_processing_fixed_minor bigint,
  add column if not exists customer_payment_processing_cross_border_bps integer,
  add column if not exists customer_payment_processing_effective_bps integer,
  add column if not exists customer_payment_processing_allowance_minor bigint,
  add column if not exists customer_estimated_processing_minor bigint,
  add column if not exists customer_min_margin_target_minor bigint,
  add column if not exists customer_min_margin_top_up_minor bigint,
  add column if not exists customer_estimated_gross_margin_minor bigint;
