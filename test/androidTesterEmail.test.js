const test = require('node:test');
const assert = require('node:assert/strict');
const { androidTesterEmail, ANDROID_TEST_URL } = require('../lib/androidTesterEmail');
const { ANDROID_INVITATION_URL, ANDROID_EMAIL_LOGO_URL } = require('../lib/androidTesterLinks');
const { verificationEmail } = require('../lib/partnerVerificationEmail');
test('Android branded invitation uses Internal Testing and does not contain a credential', () => {
  const email = androidTesterEmail(' QA+Android@HEYZIPPI.TEST ');
  assert.equal(email.subject, "You're invited to preview Zippi on Android");
  for (const value of [email.html, email.text]) {
    assert.ok(value.includes(ANDROID_INVITATION_URL)); assert.ok(!value.includes(ANDROID_TEST_URL)); assert.match(value, /Account → Partner Preview/);
    assert.match(value, /qa\+android@heyzippi.test/); assert.match(value, /six-digit/);
    assert.doesNotMatch(value, /TestFlight|\/apps\/testing\/|password|<script|<iframe|<form|file:\/\//i);
    const readable = value.replace(/<style[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, '');
    assert.doesNotMatch(readable, /\b\d{6}\b/);
  }
  assert.match(email.html, />Join Android Test</); assert.match(email.html, /support@heyzippi.com/);
  assert.ok(email.html.includes(`src="${ANDROID_EMAIL_LOGO_URL}"`));
  assert.match(email.html, /width="128" height="96" alt="Zippi"/);
  assert.doesNotMatch(email.html, /cid:|data:|file:|zippi-bunny\.png/);
  assert.equal(email.attachments, undefined);
});
test('Android invited email is normalized and escaped; non-Gmail accounts accepted', () => {
  const value = androidTesterEmail("o'neil@example.test"); assert.match(value.html, /o&#39;neil@example.test/);
  assert.throws(() => androidTesterEmail('<script>@example.test'));
});
test('OTP branding and ten-minute plain-text contract reused separately', () => {
  const email = verificationEmail({ code: '314159', expiresInSeconds: 600 });
  assert.match(email.text, /314159/); assert.match(email.text, /10 minutes/);
  assert.match(email.html, /314159/); assert.equal(email.subject, 'Your Zippi Partner Preview code');
  assert.doesNotMatch(email.html, /TestFlight|Join Android Test/);
});
