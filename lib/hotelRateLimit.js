// Only allowlisted metadata crosses the HTTP boundary. Never retain raw provider errors.
class HotelRateLimitError extends Error {
  constructor(metadata) { super('Hotel rate limit reached. Please try again later.'); this.name = 'HotelRateLimitError'; this.metadata = metadata; }
}
function zippiLimit(scope, window, limit, resetAtMs, now) {
  return new HotelRateLimitError({ source: 'ZIPPI', scope, window, limit, remaining: 0,
    resetAt: new Date(resetAtMs).toISOString(), retryAfterSeconds: Math.max(1, Math.ceil((resetAtMs - now) / 1000)) });
}
function sendHotelRateLimit(res, error) {
  const rateLimit = { ...error.metadata };
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Expose-Headers', 'Retry-After, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset');
  if (rateLimit.retryAfterSeconds !== undefined) res.setHeader('Retry-After', String(rateLimit.retryAfterSeconds));
  if (rateLimit.limit !== undefined) res.setHeader('RateLimit-Limit', String(rateLimit.limit));
  if (rateLimit.remaining !== undefined) res.setHeader('RateLimit-Remaining', String(rateLimit.remaining));
  if (rateLimit.retryAfterSeconds !== undefined) res.setHeader('RateLimit-Reset', String(rateLimit.retryAfterSeconds));
  return res.status(429).json({ ok: false, error: error.message, code: 'HOTEL_RATE_LIMITED', rateLimit });
}
function providerLimit(headers, scope, now = Date.now()) {
  const get = (key) => headers?.get?.(key);
  const integer = (value) => typeof value === 'string' && /^\d{1,9}$/.test(value) ? Number(value) : undefined;
  const date = (value) => typeof value === 'string' && value.length <= 80 && /GMT$/.test(value) && Number.isFinite(Date.parse(value)) ? Date.parse(value) : undefined;
  const metadata = { source: 'PROVIDER', scope, window: 'UNKNOWN' };
  const serverNow = date(get('date')) ?? now;
  const retry = get('retry-after');
  const seconds = integer(retry);
  const retryDate = date(retry);
  const reset = date(get('ratelimit-reset'));
  const deadline = Math.max(retryDate ?? 0, reset ?? 0, seconds === undefined ? 0 : serverNow + seconds * 1000);
  if (deadline > 0) {
    metadata.resetAt = new Date(deadline).toISOString();
    metadata.retryAfterSeconds = Math.max(0, Math.ceil((deadline - serverNow) / 1000));
  }
  for (const [field, header] of [['limit','ratelimit-limit'], ['remaining','ratelimit-remaining']]) {
    const value = integer(get(header)); if (value !== undefined) metadata[field] = value;
  }
  return new HotelRateLimitError(metadata);
}
module.exports = { HotelRateLimitError, zippiLimit, sendHotelRateLimit, providerLimit };
