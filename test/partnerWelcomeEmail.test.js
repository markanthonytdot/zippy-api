const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { invitationInstructions } = require('../lib/testerInvitationEmail');
const { createResendMailAdapter } = require('../lib/partnerAccessResendMail');
const env = { RESEND_API_KEY: 'test-only-not-a-real-key', ZIPPI_PARTNER_EMAIL_FROM: 'Zippi Partner Preview <preview@example.test>' };

test('iOS welcome contains approved content and an embedded logo, with no remote assets or tracking', () => {
  const m = invitationInstructions('ios', 'qa@example.test');
  assert.equal(m.subject, "You're invited to preview Zippi");
  for (const value of ['Get started', 'Get TestFlight', 'support@heyzippi.com', 'Thanks for exploring Zippi.', 'The Zippi Team', 'Zippi Technologies', 'Flights, Hotels and Flight + Hotel trips.']) {
    assert.ok(m.html.includes(value)); assert.ok(m.text.includes(value));
  }
  assert.match(m.html, /src="cid:zippi-bunny"/);
  assert.doesNotMatch(m.html, /<script|<iframe|<form|src="https?:|file:\/\/|localhost|127\.0\.0\.1|love to hear|feedback/i);
  assert.doesNotMatch(m.text, /<[^>]+>|love to hear|feedback/i);
  assert.equal(m.attachments.length, 1);
  assert.equal(m.attachments[0].content_id, 'zippi-bunny');
  assert.equal(m.attachments[0].content_type, 'image/png');
  assert.deepEqual(Buffer.from(m.attachments[0].content, 'base64'), fs.readFileSync(path.join(__dirname, '../admin/public/zippi-logo-nano.png')));
  const links = [...m.html.matchAll(/href="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual([...new Set(links)].sort(), ['https://apps.apple.com/app/testflight/id899247664', 'mailto:support@heyzippi.com']);
});

test('welcome payload survives persistence and reuses identical idempotent Resend content', async () => {
  const calls = [];
  const adapter = createResendMailAdapter(env, { fetchImpl: async (url, options) => {
    calls.push({url, ...options}); return { ok: true, json: async () => ({id:'mock-email'}) };
  } });
  const payload = JSON.parse(JSON.stringify(invitationInstructions('ios', 'qa@example.test')));
  for (let i=0;i<2;i++) await adapter.sendInstructions({email:'qa@example.test', ...payload, idempotencyKey:'stable-welcome-key'});
  assert.equal(calls[0].body,calls[1].body);
  assert.equal(calls[0].headers['Idempotency-Key'],calls[1].headers['Idempotency-Key']);
  assert.deepEqual(JSON.parse(calls[0].body), {from:env.ZIPPI_PARTNER_EMAIL_FROM,to:['qa@example.test'],...payload});
  assert.equal(calls[0].url,'https://api.resend.com/emails');
  assert.equal(calls[0].redirect,'error');
  assert.ok(calls[0].signal instanceof AbortSignal);
});

test('legacy stored instructions remain text-only and are not upgraded during retries', async () => {
  let body;
  const mail=createResendMailAdapter(env,{fetchImpl:async(_u,o)=>{body=JSON.parse(o.body);return {ok:true,json:async()=>({id:'mock'})};}});
  await mail.sendInstructions({email:'qa@example.test',subject:'Original',text:'Original persisted instructions',idempotencyKey:'original'});
  assert.deepEqual(body,{from:env.ZIPPI_PARTNER_EMAIL_FROM,to:['qa@example.test'],subject:'Original',text:'Original persisted instructions'});
});

test('Android instructions retain the existing platform flow and text-only payload', () => {
  const m=invitationInstructions('android');
  assert.deepEqual(Object.keys(m).sort(),['subject','text']);
  assert.match(m.text,/https:\/\/play.google.com\/apps\/testing\/com.heyzippi.app/);
  assert.doesNotMatch(m.text,/TestFlight/);
});

test('HTML provider failures remain generic with no retry or content disclosure', async () => {
  let calls=0;
  const mail=createResendMailAdapter(env,{fetchImpl:async()=>{calls++;return {ok:false,status:422};}});
  await assert.rejects(mail.sendInstructions({email:'qa@example.test',...invitationInstructions('ios', 'qa@example.test')}),e=>e.code==='mail_unavailable'&&e.message==='mail_unavailable');
  assert.equal(calls,1);
});

test('only the recipient text differs from the approved preview', () => {
  const hash = value => require('node:crypto').createHash('sha256').update(value).digest('hex');
  const m = invitationInstructions('ios', 'qa@example.test');
  assert.equal(hash(m.html.replace('qa@example.test', 'this same email address')), '06ae80759125216196331bc1171960287a23e9d35ddceda988196ba1941cc069');
  assert.equal(hash(m.text.replace('qa@example.test', 'this same email address')), 'c6ff52a744120ff97b35f293c57e4b4794a5d59d7a842b5b1b0ecf3c120a9a77');
});

test('welcome instructions use the normalized invited address in HTML and plain text', () => {
  for (const input of ['  Partner.Contact+Preview@Example.Test  ', 'another.person@example.test']) {
    const email = input.trim().toLowerCase();
    const m = invitationInstructions('ios', input);
    assert.ok(m.text.includes(`Open Zippi and enter ${email} when prompted for Partner Preview access.`));
    assert.ok(m.html.includes(`>${email}</strong> when prompted for Partner Preview access.`));
    assert.doesNotMatch(m.html + m.text, /INVITED_EMAIL|this same email address/);
    assert.equal(m.html.split(email).length - 1, 1);
    assert.equal(m.text.split(email).length - 1, 1);
  }
});

test('email rendering escapes HTML while preserving plus tags and literal replacement characters', () => {
  const email = "o'connor+$&@example.test";
  const m = invitationInstructions('ios', email);
  assert.ok(m.html.includes('o&#39;connor+$&amp;@example.test'));
  assert.ok(m.text.includes(`enter ${email} when prompted`));
  assert.doesNotMatch(m.html, /INVITED_EMAIL/);
});

test('iOS instructions cannot render without a valid recipient', () => {
  for (const email of [undefined, '', '<img src=x onerror=alert(1)>@example.test', 'a@example.test\r\nBcc:other@example.test']) {
    assert.throws(() => invitationInstructions('ios', email), error => error.code === 'invalid_email');
  }
});
