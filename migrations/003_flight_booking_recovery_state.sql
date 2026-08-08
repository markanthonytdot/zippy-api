alter table flight_booking_sessions
  add column if not exists duffel_post_started_at timestamptz;

alter table flight_booking_sessions
  drop constraint if exists flight_booking_sessions_booking_status_check;

alter table flight_booking_sessions
  add constraint flight_booking_sessions_booking_status_check check (booking_status in (
    'payment_setup', 'awaiting_payment', 'payment_paid', 'booking_in_progress',
    'booking_unknown', 'booking_failed_refunded', 'booking_failed_refund_pending',
    'payment_canceled', 'confirmed'
  ));
