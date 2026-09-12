const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { registerAndroidTesterPublicRoutes, ANDROID_TEST_URL, ANDROID_INVITATION_URL, ANDROID_EMAIL_LOGO_URL } = require('../lib/androidTesterLinks');
const { androidTesterEmail } = require('../lib/androidTesterEmail');
const { createResendMailAdapter } = require('../lib/partnerAccessResendMail');

async function server(t) {
  const app = express(); app.use(helmet()); registerAndroidTesterPublicRoutes(app);
  // Anything not handled by the public route is still protected normally.
  app.use((_req, res) => res.sendStatus(401));
  const s = await new Promise(resolve => { const x = app.listen(0, '127.0.0.1', () => resolve(x)); });
  t.after(() => new Promise(resolve => { s.closeAllConnections(); s.close(resolve); }));
  return `http://127.0.0.1:${s.address().port}`;
}

test('branded CTA is fixed, anonymous, and cannot become an open redirect', async t => {
  const base = await server(t);
  assert.equal(ANDROID_INVITATION_URL, 'https://admin.heyzippi.com/android-test');
  assert.equal(ANDROID_TEST_URL, 'https://play.google.com/apps/internaltest/4701051442738255142');
  for (const suffix of ['', '?url=https://evil.example', '?next=//evil.example&redirect_uri=https://evil.example', '?destination=%0d%0aLocation:evil']) {
    const r = await fetch(base + '/android-test' + suffix, { redirect: 'manual' });
    assert.equal(r.status, 302); assert.equal(r.headers.get('location'), ANDROID_TEST_URL);
    assert.equal(r.headers.get('set-cookie'), null);
    assert.ok(!(await r.text()).includes('evil'));
  }
  const head = await fetch(base + '/android-test', { method: 'HEAD', redirect: 'manual' });
  assert.equal(head.status, 302); assert.equal(await head.text(), '');
  assert.equal((await fetch(base + '/android-test', { method: 'POST', redirect: 'manual' })).status, 401);
  assert.equal((await fetch(base + '/android-test/anything', { redirect: 'manual' })).status, 401);
});

test('email PNG resolves anonymously with fixed bytes and proxy-compatible public headers', async t => {
  const base = await server(t); const imagePath = new URL(ANDROID_EMAIL_LOGO_URL).pathname;
  const r = await fetch(base + imagePath);
  assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /^image\/png/);
  assert.equal(r.headers.get('content-disposition'), null);
  assert.equal(r.headers.get('set-cookie'), null);
  assert.equal(r.headers.get('cross-origin-resource-policy'), 'cross-origin');
  assert.match(r.headers.get('cache-control'), /public.*immutable/);
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.deepEqual(bytes, fs.readFileSync(path.join(__dirname, '../admin/public/zippi-logo-nano.png')));
  assert.equal(bytes.readUInt32BE(16), 512); assert.equal(bytes.readUInt32BE(20), 382);
  const head = await fetch(base + imagePath, { method: 'HEAD' }); assert.equal(head.status, 200);
  assert.equal(Number(head.headers.get('content-length')), bytes.length);
});

test('actual Resend adapter sends Android HTML/text without attachment or CID fields', async () => {
  let calls = 0;
  const mail = createResendMailAdapter({ RESEND_API_KEY: 'mock-only', ZIPPI_PARTNER_EMAIL_FROM: 'Zippi <support@heyzippi.com>' }, {
    fetchImpl: async (url, options) => {
      calls++; assert.equal(url, 'https://api.resend.com/emails');
      const body = JSON.parse(options.body);
      assert.equal(body.from, 'Zippi <support@heyzippi.com>');
      assert.deepEqual(body.to, ['email-fixture@heyzippi.test']);
      assert.equal(body.attachments, undefined); assert.ok(body.html && body.text);
      assert.doesNotMatch(body.html, /cid:|data:|file:|base64|play\.google\.com|check.*spam/i);
      assert.doesNotMatch(body.text, /play\.google\.com|check.*spam/i);
      const urls = [...body.html.matchAll(/(?:href|src)="(https:[^"]+)"/g)].map(match => new URL(match[1]));
      assert.equal(urls.length, 2); assert.ok(urls.every(u => u.origin === 'https://admin.heyzippi.com'));
      assert.ok(urls.some(u => u.href === ANDROID_INVITATION_URL)); assert.ok(urls.some(u => u.href === ANDROID_EMAIL_LOGO_URL));
      assert.match(body.html, /<img[^>]*width="128" height="96" alt="Zippi"/);
      assert.ok(body.text.includes(ANDROID_INVITATION_URL));
      assert.equal(options.headers['Idempotency-Key'], 'local-only-idempotency-fixture');
      return { ok: true, json: async () => ({ id: 'mock-message-id' }) };
    },
  });
  await mail.sendInstructions({ email: 'email-fixture@heyzippi.test', ...androidTesterEmail('email-fixture@heyzippi.test'), idempotencyKey: 'local-only-idempotency-fixture' });
  assert.equal(calls, 1);
});
