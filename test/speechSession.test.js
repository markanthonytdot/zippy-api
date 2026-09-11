const test = require('node:test'), assert = require('node:assert/strict');
const express = require('express');
const { createSpeechSessionHandler } = require('../lib/speechSession');
const { createSpeechSessionLimits, speechRequestIp } = require('../lib/speechSessionLimits');
const fixtureKey = 'server-only-test-fixture', token = 'eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.signature';
const valid = () => new Response(JSON.stringify({ access_token: token, expires_in: 30 }));
async function harness(t, options = {}) {
  const calls = [], logs = [];
  const app = express(); app.use(express.json({ limit: '2kb' }));
  app.use('/v1/speech/session', createSpeechSessionHandler({ env: { DEEPGRAM_SERVER_API_KEY: fixtureKey },
    fetch: async (url, opt) => { calls.push({ url, opt }); return valid(); }, log: x => logs.push(x), ...options }));
  const server = app.listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/speech/session`;
  return { url, calls, logs, request: (body = {}, headers = {}) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-user-id': 'guest-fixture', ...headers }, body: JSON.stringify(body) }) };
}
test('guest gets only ephemeral Bearer credential; fixed grant body and no-store', async t => {
  const h = await harness(t), r = await h.request(), body = await r.json();
  assert.equal(r.status, 200); assert.equal(r.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(body).sort(), ['accessToken', 'expiresInSeconds', 'ok', 'tokenType']);
  assert.equal(body.accessToken, token); assert.equal(body.tokenType, 'Bearer'); assert(body.expiresInSeconds <= 30);
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0].url, 'https://api.deepgram.com/v1/auth/grant');
  assert.equal(h.calls[0].opt.headers.Authorization, `Token ${fixtureKey}`);
  assert.deepEqual(JSON.parse(h.calls[0].opt.body), { ttl_seconds: 30 });
  assert(!JSON.stringify(body).includes(fixtureKey)); assert(!JSON.stringify(h.logs).includes(token));
});
for (const body of [{ project: 'other' }, { ttl_seconds: 3600 }, { key: 'secret' }, { qa: true }, [], null]) {
  test(`invalid request cannot select project/ttl/admin/bypass: ${JSON.stringify(body)}`, async t => {
    const h = await harness(t), r = await h.request(body); assert([400].includes(r.status)); assert.equal(h.calls.length, 0);
  });
}
test('origin, device, method and subpath validation', async t => {
  const h = await harness(t);
  assert.equal((await h.request({}, { origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await h.request({}, { 'x-user-id': '' })).status, 400);
  assert.equal((await fetch(h.url)).status, 405);
  assert.equal((await fetch(h.url + '/keys', { method: 'POST' })).status, 404);
  const preflight = await fetch(h.url, { method: 'OPTIONS', headers: { Origin: 'https://heyzippi.com' } });
  assert.equal(preflight.status, 204); assert.equal(h.calls.length, 0);
});
test('missing server key fails safely without issuing', async t => {
  const h = await harness(t, { env: {} }); assert.equal((await h.request()).status, 503); assert.equal(h.calls.length, 0);
});
for (const status of [400, 401, 403, 429, 500]) test(`grant ${status} is sanitized and never automatically retried`, async t => {
  let n = 0; const h = await harness(t, { fetch: async () => { n++; return new Response('private-key-and-provider-error', { status }); } });
  const r = await h.request(); assert.equal(r.status, 503); assert(!(await r.text()).includes('private-key')); assert.equal(n, 1);
  assert(!JSON.stringify(h.logs).includes('private-key'));
});
for (const value of ['not json', JSON.stringify({ access_token: fixtureKey, expires_in: 30 }), JSON.stringify({ access_token: token, expires_in: 3600 }), JSON.stringify({ access_token: token, expires_in: 0 }), 'x'.repeat(17000)]) {
  test(`invalid grant body is redacted (${value.length} bytes)`, async t => {
    const h = await harness(t, { fetch: async () => new Response(value) }); const r = await h.request();
    assert.equal(r.status, 503); assert(!(await r.text()).includes(fixtureKey));
  });
}
test('network exception is sanitized', async t => {
  const h = await harness(t, { fetch: async () => { throw new Error(fixtureKey); } });
  assert.equal((await h.request()).status, 503); assert(!JSON.stringify(h.logs).includes(fixtureKey));
});
test('grant timeout aborts upstream and offers recoverable failure', async t => {
  let aborted = false;
  const h = await harness(t, { timeoutMs: 15, fetch: async (_, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error(fixtureKey)); })) });
  const r = await h.request(); assert.equal(r.status, 503); assert.equal((await r.json()).code, 'speech_timeout'); assert(aborted);
});
test('body-read timeout is also bounded', async t => {
  const h = await harness(t, { timeoutMs: 15, fetch: async (_, { signal }) => new Response(new ReadableStream({ start(controller) { signal.addEventListener('abort', () => controller.error(new Error('cancelled'))); } })) });
  const r = await h.request(); assert.equal(r.status, 503); assert.equal((await r.json()).code, 'speech_timeout');
});
test('caller cancellation aborts grant and publishes no credential', async t => {
  let started, aborted; const ready = new Promise(r => started = r), cancelled = new Promise(r => aborted = r);
  const h = await harness(t, { fetch: async (_, { signal }) => new Promise((_, reject) => { signal.addEventListener('abort', () => { aborted(); reject(new Error('cancelled')); }); started(); }) });
  const controller = new AbortController(); const request = fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-user-id': 'guest' }, body: '{}', signal: controller.signal }).catch(() => {});
  await ready; controller.abort(); await cancelled; await request;
  assert(!h.logs.some(x => x.outcome === 'issued'));
});
test('IP quota cannot be bypassed by rotating device IDs; reset permits reacquisition', async t => {
  let time = 1000; const budget = createSpeechSessionLimits({ now: () => time, limits: { ipMinute: 1 } });
  const h = await harness(t, { budget }); assert.equal((await h.request()).status, 200);
  const r = await h.request({}, { 'x-user-id': 'another', 'x-qa': 'true' }); assert.equal(r.status, 429); assert.equal(r.headers.get('retry-after'), '59'); assert.equal(h.calls.length, 1);
  time = 61000; assert.equal((await h.request()).status, 200);
});
test('global and device caps remain independent; no unbounded/disabled configuration', () => {
  const budget = createSpeechSessionLimits({ now: () => 1000, limits: { globalMinute: 2, deviceMinute: 1 } });
  assert(budget.take({ device: 'a', ip: 'a' }).ok); assert(!budget.take({ device: 'a', ip: 'b' }).ok);
  assert(budget.take({ device: 'b', ip: 'b' }).ok); assert(!budget.take({ device: 'c', ip: 'c' }).ok);
  assert.throws(() => createSpeechSessionLimits({ limits: { globalMinute: 0 } }));
});
test('forwarded spoof prefix cannot vary Render edge IP; direct requests ignore XFF', () => {
  const req = { headers: { 'x-forwarded-for': '1.1.1.1, 203.0.113.2' }, socket: { remoteAddress: '127.0.0.1' } };
  assert.equal(speechRequestIp(req, true), '203.0.113.2'); assert.equal(speechRequestIp(req, false), '127.0.0.1');
  req.headers['x-forwarded-for'] = '2.2.2.2, 203.0.113.2'; assert.equal(speechRequestIp(req, true), '203.0.113.2');
});
