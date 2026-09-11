const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { invitationInstructions } = require('../lib/testerInvitationEmail');
const { createResendMailAdapter } = require('../lib/partnerAccessResendMail');
const env = { RESEND_API_KEY: 'test-only-not-a-real-key', ZIPPI_PARTNER_EMAIL_FROM: 'Zippi Partner Preview <preview@example.test>' };

test('iOS welcome contains approved content and an embedded logo, with no remote assets or tracking', () => {
  const m = invitationInstructions('ios');
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
  const payload = JSON.parse(JSON.stringify(invitationInstructions('ios')));
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
  await assert.rejects(mail.sendInstructions({email:'qa@example.test',...invitationInstructions('ios')}),e=>e.code==='mail_unavailable'&&e.message==='mail_unavailable');
  assert.equal(calls,1);
});

test('HTML and fallback match the approved preview byte for byte', () => {
  const hash = value => require('node:crypto').createHash('sha256').update(value).digest('hex');
  const m = invitationInstructions('ios');
  assert.equal(hash(m.html), '06ae80759125216196331bc1171960287a23e9d35ddceda988196ba1941cc069');
  assert.equal(hash(m.text), 'c6ff52a744120ff97b35f293c57e4b4794a5d59d7a842b5b1b0ecf3c120a9a77');
});
