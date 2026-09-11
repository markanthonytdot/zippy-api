const { zippiLimit } = require('./hotelRateLimit');
// Finite, process-local protection. Shared external counters are required for multiple replicas.
function positive(value, fallback) { const n = Number(value); return Number.isSafeInteger(n) && n > 0 ? n : fallback; }
function createHotelReadBudget({ env = process.env, now = Date.now } = {}) {
  const limits = { MINUTE: positive(env.HOTELS_RPM, 10), HOUR: positive(env.HOTELS_HOURLY, 50), DAY: positive(env.HOTELS_DAILY, 100) };
  // No deployment can silently increase the aggregate above the corresponding identity ceiling.
  const aggregate = Object.fromEntries(Object.entries(limits).map(([w,n]) => [w, Math.min(n, positive(env[`HOTEL_PROVIDER_${w}`], n))]));
  const traffic = env.HOTEL_TRAFFIC_CLASS === 'QA' ? 'QA' : 'CONSUMER';
  const entries = new Map(); let nextPrune = 0;
  function prepare(prefix, windows, scope) {
    const time = now();
    if (time >= nextPrune) { for (const [k,v] of entries) if (v.reset <= time) entries.delete(k); nextPrune = time + 60000; }
    return Object.entries(windows).map(([window,limit]) => {
      const key = `${prefix}:${window}`; let entry = entries.get(key);
      const duration = window === 'MINUTE' ? 60000 : window === 'HOUR' ? 3600000 : 86400000;
      if (!entry || entry.reset <= time) entry = { count: 0, reset: window === 'MINUTE' ? time + duration : (Math.floor(time / duration) + 1) * duration };
      return { key, entry, limit, scope, window };
    });
  }
  function debit(groups) {
    const rows = groups.flat(); const exhausted = rows.filter(r => r.entry.count >= r.limit).sort((a,b) => b.entry.reset - a.entry.reset);
    if (exhausted.length) { const r = exhausted[0]; throw zippiLimit(r.scope,r.window,r.limit,r.entry.reset,now()); }
    // Check every identity/aggregate window before committing any debit.
    for (const r of rows) { r.entry.count++; entries.set(r.key,r.entry); }
  }
  return {
    traffic,
    api(identity) { debit([prepare(`api:${traffic}:${identity}`, { MINUTE: limits.MINUTE }, 'API')]); },
    provider(identity, provider, operation) {
      debit([prepare(`identity:${traffic}:${identity}:${operation}`, limits, operation),
        prepare(`provider:${provider}`, aggregate, 'PROVIDER_TOTAL')]);
    },
  };
}
module.exports = { createHotelReadBudget };
