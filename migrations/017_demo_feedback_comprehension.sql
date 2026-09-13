-- Additive update: preserve every earlier free-text answer and timestamp.
-- NULL identifies the earlier question format; never infer a choice from text.
alter table demo_feedback_responses add column comprehension_choice text
  check (comprehension_choice in (
    'natural_language_flight_search', 'deals_and_price_alerts',
    'automatic_trip_booking', 'general_travel_chatbot', 'not_sure'
  ));

-- Reuse the existing text columns: understanding = optional own words;
-- reason = optional additional comments. Existing rows retain their original meaning.
alter table demo_feedback_responses drop constraint demo_feedback_responses_understanding_check;
alter table demo_feedback_responses alter column understanding set default '';
alter table demo_feedback_responses add constraint demo_feedback_responses_understanding_check
  check (char_length(understanding) <= 2000);
