// Test child only: real Express and real HTTP fetch, with all external network
// replaced by a loopback provider. Never loaded by the deployed start command.
const realFetch = global.fetch;
const origin = process.env.HOTEL_FIXTURE_ORIGIN;
if (process.env.NODE_ENV !== 'test' || !/^http:\/\/127\.0\.0\.1:\d+$/.test(origin || '')) throw new Error('Loopback fixture required');
global.fetch = (url, options) => {
  const target = String(url);
  if (target.startsWith('https://api.duffel.com/stays/')) return realFetch(origin + new URL(target).pathname, options);
  if (target === 'https://open.er-api.com/v6/latest/USD') return Promise.resolve(new Response('{}', {status:200}));
  throw new Error('External requests forbidden in hotel staging tests');
};
