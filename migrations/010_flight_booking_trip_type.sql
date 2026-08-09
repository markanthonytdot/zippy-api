alter table flight_booking_sessions
  add column if not exists trip_type text;

update flight_booking_sessions
set trip_type = case
  when jsonb_typeof(offer_snapshot->'slices') = 'array'
    and jsonb_array_length(offer_snapshot->'slices') = 2
    then 'round_trip_single_offer'
  else 'one_way'
end
where trip_type is null;

alter table flight_booking_sessions
  drop constraint if exists flight_booking_sessions_trip_type_check;

alter table flight_booking_sessions
  add constraint flight_booking_sessions_trip_type_check check (
    trip_type in ('one_way', 'round_trip_single_offer')
  );
