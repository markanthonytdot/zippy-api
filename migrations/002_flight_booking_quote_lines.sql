alter table flight_booking_sessions
  add column if not exists base_fare_minor bigint,
  add column if not exists taxes_minor bigint;

update flight_booking_sessions
set base_fare_minor = offer_minor
where base_fare_minor is null;

alter table flight_booking_sessions
  alter column base_fare_minor set not null;
