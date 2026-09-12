// Days are elapsed 24-hour periods in server UTC, never calendar-midnight boundaries.
const ACCESS_DURATION_DAYS = Object.freeze([1, 3, 7, 14, 30]);
const MAX_ACCESS_DURATION_DAYS = 90;
const validAccessDuration = value => Number.isInteger(value) && value >= 1 && value <= MAX_ACCESS_DURATION_DAYS;
module.exports = { ACCESS_DURATION_DAYS, MAX_ACCESS_DURATION_DAYS, validAccessDuration };
