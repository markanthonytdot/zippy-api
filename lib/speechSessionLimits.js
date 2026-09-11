const { createHmac, randomBytes } = require('node:crypto');
const { isIP } = require('node:net');

// Independent IP/global buckets prevent rotating an unverified device ID from granting extra quota.
function createSpeechSessionLimits({ now = Date.now, limits = {} } = {}) {
  const salt = randomBytes(32), buckets = new Map();
  const rules = [
    ['device', 60000, limits.deviceMinute ?? 6], ['device', 3600000, limits.deviceHour ?? 60],
    ['ip', 60000, limits.ipMinute ?? 30], ['ip', 3600000, limits.ipHour ?? 300],
    ['global', 60000, limits.globalMinute ?? 120], ['global', 86400000, limits.globalDay ?? 2000],
  ];
  if (rules.some(([, , n]) => !Number.isInteger(n) || n < 1 || n > 2000)) throw new Error('Invalid speech limit');
  return {
    take({ device, ip }) {
      const time = now();
      for (const [key, value] of buckets) if (value.reset <= time) buckets.delete(key);
      const entries = rules.map(([scope, window, max]) => {
        const identity = scope === 'global' ? 'all' : scope === 'device' ? device : ip;
        const key = createHmac('sha256', salt).update(`${scope}:${window}:${identity}`).digest('hex');
        return { key, max, value: buckets.get(key) || { count: 0, reset: (Math.floor(time / window) + 1) * window } };
      });
      const blocked = entries.filter(x => x.value.count >= x.max);
      if (blocked.length) return { ok: false, retryAfter: Math.max(1, Math.ceil((Math.max(...blocked.map(x => x.value.reset)) - time) / 1000)) };
      // Fail closed on saturation rather than evicting live counters and resetting someone's quota.
      if (buckets.size + entries.filter(x => !buckets.has(x.key)).length > 8192) return { ok: false, retryAfter: 60 };
      for (const x of entries) { x.value.count++; buckets.set(x.key, x.value); }
      return { ok: true };
    },
  };
}

function speechRequestIp(req, onRender) {
  // Render appends its edge-observed client to XFF. Ignore caller-prepended entries.
  // Trust forwarded headers only in the Render runtime; direct/local callers use their socket.
  const forwarded = onRender ? String(req.headers['x-forwarded-for'] || '').split(',').map(x => x.trim()).filter(Boolean) : [];
  const raw = forwarded.at(-1) || req.socket?.remoteAddress || 'unknown';
  return isIP(raw) ? raw.replace(/^::ffff:/, '') : 'unknown';
}

module.exports = { createSpeechSessionLimits, speechRequestIp };
