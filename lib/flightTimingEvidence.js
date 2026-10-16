const { Temporal } = require('@js-temporal/polyfill');

function elapsedMinutes(start, end) {
  if (!start || !end) return null;
  try {
    const nanoseconds = Temporal.Instant.from(end).epochNanoseconds - Temporal.Instant.from(start).epochNanoseconds;
    if (nanoseconds < 0n || nanoseconds % 60000000000n !== 0n) return null;
    const minutes = Number(nanoseconds / 60000000000n);
    return Number.isSafeInteger(minutes) ? minutes : null;
  } catch { return null; }
}

// Request-scoped caches avoid resolving the same scheduled flight for every
// fare. Nothing here changes provider queries, slice totals or ranking.
function createFlightTimingEvidence() {
  const zones = new Map(), instants = new Map();
  function timeZone(value) {
    if (typeof value !== 'string' || value.length > 100 || !value
        || /^[+-]/.test(value)) return null;
    if (!zones.has(value)) {
      try {
        Temporal.Instant.fromEpochMilliseconds(0).toZonedDateTimeISO(value);
        zones.set(value, value);
      } catch { zones.set(value, null); }
    }
    return zones.get(value);
  }
  function utc(value, zone) {
    if (typeof value !== 'string' || value.length > 80) return null;
    const key = JSON.stringify([value, zone]);
    if (instants.has(key)) return instants.get(key);
    let result = null;
    try {
      // No loose Date parsing, calendar overflow, leap-second repair or viewer
      // timezone. Offsets stay exactly as provided in the original schedule.
      const match = /^(\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,9})?)?)(Z|[+-]\d{2}:\d{2})?$/.exec(value);
      if (match) {
        const local = Temporal.PlainDateTime.from(match[1], { overflow: 'reject' });
        if (match[2] === '-00:00') {
          // RFC 3339 uses this spelling for an unknown local offset.
          result = null;
        } else if (match[2]) {
          const instant = Temporal.Instant.from(value);
          // Z is explicitly UTC. A numeric local offset must agree with the
          // supplied IANA zone, if one exists (including a repeated DST hour).
          if (!zone || match[2] === 'Z' || instant.toZonedDateTimeISO(zone).toPlainDateTime().equals(local)) result = instant.toString();
        } else if (zone) {
          result = local.toZonedDateTime(zone, { disambiguation: 'reject' }).toInstant().toString();
        }
      }
    } catch { /* Missing/invalid/ambiguous evidence stays unavailable. */ }
    instants.set(key, result);
    return result;
  }
  return { timeZone, utc };
}

module.exports = { createFlightTimingEvidence, elapsedMinutes };
