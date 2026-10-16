const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createFlightTimingEvidence } = require('../lib/flightTimingEvidence');
const { normalizeOffer, buildFlightSearchContract } = require('../lib/flightSearchContract');
const real = require('./fixtures/flight-timing-real.json');

const segment = (departure, arrival, originZone, destinationZone, duration) => ({
  departing_at: departure, arriving_at: arrival, duration,
  origin: { iata_code: 'YVR', time_zone: originZone },
  destination: { iata_code: 'YYZ', time_zone: destinationZone },
});
const normalized = s => normalizeOffer({ slices: [{ segments: [s] }] }).slices[0].segments[0];

test('real YYZ-DCA-MIA preserves supplier duration and full timezone evidence without mutation', () => {
  const raw = { id: 'captured-schedule-only', slices: [structuredClone(real.slice)] }, before = structuredClone(raw);
  const out = normalizeOffer(raw), [a, b] = out.slices[0].segments;
  assert.deepEqual(raw, before);
  assert.equal(a.durationMinutes, 120); assert.equal(b.durationMinutes, 168);
  assert.equal(a.origin.timeZone, 'America/Toronto'); assert.equal(a.destination.timeZone, 'America/New_York');
  assert.equal(a.arrivingAtUtc, '2026-12-02T00:13:00Z'); assert.equal(b.departingAtUtc, '2026-12-02T00:59:00Z');
  assert.equal((Date.parse(b.departingAtUtc) - Date.parse(a.arrivingAtUtc)) / 60000, 46);
  assert.equal(a.departingAt, '2026-12-01T17:13:00'); assert.equal(b.arrivingAt, '2026-12-01T22:47:00');
  assert.equal(out.slices[0].durationMinutes, 334);
});

test('airport-local cross-zone overnight dates resolve with their supplied IANA zones', () => {
  const s = normalized(segment('2026-12-01T18:00:00', '2026-12-02T02:00:00', 'America/Vancouver', 'America/Toronto', 'PT5H'));
  assert.equal(s.departingAtUtc, '2026-12-02T02:00:00Z'); assert.equal(s.arrivingAtUtc, '2026-12-02T07:00:00Z');
  assert.equal(s.durationMinutes, 300);
});

test('valid UTC endpoints can supply a missing segment duration, without changing slice totals/ranking', () => {
  const raw = { id: 'a', slices: [{ segments: [segment('2026-12-01T18:00:00', '2026-12-02T02:00:00', 'America/Vancouver', 'America/Toronto')] }] };
  const c = buildFlightSearchContract([raw]);
  assert.equal(c.offers[0].slices[0].segments[0].durationMinutes, 300);
  assert.equal(c.offers[0].slices[0].durationMinutes, null); assert.equal(c.offers[0].totalDurationMinutes, null);
  assert.equal(c.rankingAvailability.fastest, false);
});

test('bare clocks without supplied zones never acquire inferred UTC or elapsed time', () => {
  const s = normalized(segment('2026-12-01T18:00:00', '2026-12-02T02:00:00'));
  assert.equal(s.departingAtUtc, null); assert.equal(s.arrivingAtUtc, null); assert.equal(s.durationMinutes, null);
  assert.equal(s.origin.timeZone, null); assert.equal(s.destination.timeZone, null);
  const supplied = normalized(segment('2026-12-01T18:00:00', '2026-12-02T02:00:00', null, null, 'PT5H'));
  assert.equal(supplied.durationMinutes, 300); assert.equal(supplied.departingAtUtc, null);
});

test('repeated DST hour and spring gap are unavailable without disambiguating offset evidence', () => {
  const t = createFlightTimingEvidence();
  for (const value of ['2026-11-01T01:30:00', '2026-03-08T02:30:00']) assert.equal(t.utc(value, 'America/New_York'), null);
  assert.equal(t.utc('2026-11-01T01:30:00-04:00', 'America/New_York'), '2026-11-01T05:30:00Z');
  assert.equal(t.utc('2026-11-01T01:45:00-05:00', 'America/New_York'), '2026-11-01T06:45:00Z');
});

test('half-hour DST transitions are strict as well', () => {
  const t = createFlightTimingEvidence();
  assert.equal(t.utc('2026-04-05T01:45:00', 'Australia/Lord_Howe'), null);
  assert.equal(t.utc('2026-10-04T02:15:00', 'Australia/Lord_Howe'), null);
  assert.equal(t.utc('2026-04-05T01:45:00+11:00', 'Australia/Lord_Howe'), '2026-04-04T14:45:00Z');
});

test('explicit offsets work without airport zones; conflicting zone/offset does not get silently repaired', () => {
  const t = createFlightTimingEvidence();
  assert.equal(t.utc('2026-12-01T18:00:00-08:00', null), '2026-12-02T02:00:00Z');
  assert.equal(t.utc('2026-12-01T18:00:00-04:00', 'America/New_York'), null);
  assert.equal(t.utc('2026-12-01T18:00:00Z', 'America/New_York'), '2026-12-01T18:00:00Z');
  assert.equal(t.utc('2026-12-01T18:00:00-00:00', null), null);
});

test('invalid dates, leap seconds, offsets, zones and durations remain unavailable', () => {
  const t = createFlightTimingEvidence();
  for (const value of ['', undefined, '2026-02-30T18:00:00', '2026-12-01T24:00:00', '2026-12-01T18:00:60', '2026-12-01T18:00:00+99:00']) assert.equal(t.utc(value, 'America/New_York'), null);
  for (const zone of [null, 123, 'Not/A_Zone', '+04:00', 'x'.repeat(101)]) assert.equal(t.timeZone(zone), null);
  for (const d of ['PT0M', 'P', 'junk', 'PT999999999999999999999999H']) {
    assert.equal(normalized(segment('', '', null, null, d)).durationMinutes, null);
  }
});

test('derived minutes do not round fractional seconds into a fabricated whole minute', () => {
  const s = normalized(segment('2026-12-01T18:00:00.0001Z', '2026-12-01T18:01:00Z'));
  assert.equal(s.durationMinutes, null);
  const exact = normalized(segment('2026-12-01T18:00:00.0001Z', '2026-12-01T18:01:00.0001Z'));
  assert.equal(exact.durationMinutes, 1);
});

test('request-scoped resolution returns the same evidence for repeated fare segments', () => {
  const raw = { id: 'a', slices: [structuredClone(real.slice)] };
  const c = buildFlightSearchContract([raw, { ...structuredClone(raw), id: 'b' }]);
  assert.deepEqual(c.offers[0].slices, c.offers[1].slices);
  assert.equal(c.contractVersion, 1);
});

test('additive fields preserve the exact legacy contract, prices, baggage and ranking', () => {
  const fixture = require('./fixtures/flight-timing-legacy-compatibility.json');
  const before = structuredClone(fixture.raw), current = buildFlightSearchContract(fixture.raw);
  for (const offer of current.offers) for (const slice of offer.slices) for (const s of slice.segments) {
    delete s.departingAtUtc; delete s.arrivingAtUtc; delete s.durationMinutes;
    delete s.origin.timeZone; delete s.destination.timeZone;
  }
  assert.deepEqual(current, fixture.expected);
  assert.deepEqual(fixture.raw, before);
});
