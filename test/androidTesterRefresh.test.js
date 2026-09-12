const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../admin/public/android-testers.js'), 'utf8');

// Execute the shipped UI controller with a small DOM and a controllable HTTP boundary.
// Only synthetic data is used; no live services, email or tester records are touched.
function ui(fetchImpl) {
  class Element {
    constructor(tag = 'div') { this.tag = tag; this.children = []; this.listeners = {}; this.textContent = ''; this.dataset = {}; }
    addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
    async fire(name, event = {}) { for (const fn of this.listeners[name] || []) await fn({ target: this, preventDefault() {}, ...event }); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute() {} showModal() {} close() {} focus() {}
    remove() { body.children = body.children.filter(child => child !== this); }
  }
  const nodes = new Map(); const get = id => { if (!nodes.has(id)) nodes.set(id, new Element()); return nodes.get(id); };
  const body = new Element('body'); const form = get('tester-invite-form');
  form.elements = { platform: { value: 'android' }, email: { value: 'refresh-fixture@heyzippi.test' } };
  const radio = new Element('input'); const organization = new Element();
  form.querySelector = selector => selector.startsWith('input') ? radio : organization;
  const document = { body, createElement: tag => new Element(tag), getElementById: get,
    querySelectorAll: () => [], addEventListener() {} };
  vm.runInNewContext(source, { document, fetch: fetchImpl, Date, setTimeout, clearTimeout });
  const descendants = element => element.children.flatMap(child => [child, ...descendants(child)]);
  const find = (element, label) => descendants(element).find(child => child.tag === 'button' && child.textContent === label);
  return { get, form, body, button: label => find(get('android-tester-rows'), label),
    async confirm() {
      const operation = this.button('Confirm Play eligibility').fire('click');
      await find(body, 'Confirm').fire('click'); await operation;
    },
    refresh: () => get('tester-refresh').fire('click'),
    message: () => get('tester-invite-message').textContent };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function result(eligibility = 'not_confirmed') {
  return { ok: true, config: { enabled: true, policyConfigured: true, emailConfigured: true, durationDays: 7 },
    invitations: [{ id: '00000000-0000-4000-8000-000000000001', email: 'refresh-fixture@heyzippi.test', access: 'active',
      playEligibility: eligibility, emailStatus: 'not_sent' }] };
}
const response = data => ({ ok: true, json: async () => data });

test('successful explicit refresh clears stale Android action error and reflects persisted confirmation', async () => {
  let confirmed = false; const calls = [];
  const app = ui(async (url, options) => {
    calls.push({ url, method: options.method, body: options.body && JSON.parse(options.body) });
    if (options.method === 'POST') throw new TypeError('Load failed');
    return response(result(confirmed ? 'confirmed' : 'not_confirmed'));
  });
  await tick();
  assert.equal(app.message(), ''); assert.equal(app.button('Send Android invitation').disabled, true);
  await app.confirm();
  assert.equal(app.message(), 'Load failed');
  // Another authorized session has since confirmed the existing record.
  confirmed = true;
  await app.refresh();
  assert.equal(app.message(), '');
  assert.equal(app.button('Send Android invitation').disabled, false);
  assert.equal(app.button('Confirm Play eligibility'), undefined);
  assert.deepEqual(calls.filter(call => call.method === 'POST').map(call => call.body.action), ['confirm']);
  assert.ok(calls.every(call => call.url === '/admin/api/android-testers'));
});

test('failed refresh retains visible load warning and does not mutate or send', async () => {
  let fail = false; let writes = 0;
  const app = ui(async (_url, options) => {
    if (options.method === 'POST') writes++;
    if (fail) throw new TypeError('Load failed');
    return response(result('confirmed'));
  });
  await tick(); fail = true; await app.refresh();
  assert.match(app.message(), /could not be confirmed/);
  assert.ok(app.button('Mark not confirmed')); assert.equal(writes, 0);
  fail = false; await app.refresh(); assert.equal(app.message(), '');
});

test('Android refresh does not clear an iOS or other unrelated message', async () => {
  const app = ui(async () => response(result('confirmed'))); await tick();
  app.get('tester-invite-message').textContent = 'An iOS operation needs review.';
  await app.refresh(); assert.equal(app.message(), 'An iOS operation needs review.');
  app.form.elements.platform.value = 'ios';
  await app.refresh(); assert.equal(app.message(), 'An iOS operation needs review.');
});

test('refresh cannot clear or duplicate an in-flight action', async () => {
  let finish; let reads = 0; let writes = 0;
  const app = ui(async (_url, options) => {
    if (options.method === 'POST') { writes++; return new Promise(resolve => { finish = resolve; }); }
    reads++; return response(result());
  });
  await tick(); const action = app.confirm(); await tick(); const readsBefore = reads;
  await app.refresh();
  assert.equal(app.message(), 'Updating production Android tester access…'); assert.equal(reads, readsBefore);
  finish(response({ invitation: { error: null } })); await action;
  assert.equal(app.message(), 'Manual Play eligibility confirmed. No email sent.'); assert.equal(writes, 1);
});

test('post-send inbox guidance appears only after provider-accepted delivery', async () => {
  for (const status of ['not_sent', 'sending', 'failed', 'sent']) {
    let writes = 0; const data = result('confirmed'); data.invitations[0].emailStatus = status;
    const app = ui(async (_url, options) => { if (options.method !== 'GET') writes++; return response(data); });
    await tick();
    const paragraphs = app.get('android-tester-rows').children[0].children.filter(e => e.tag === 'p').map(e => e.textContent);
    const guidance = paragraphs.filter(text => text.includes('Spam or Promotions'));
    assert.equal(guidance.length, status === 'sent' ? 1 : 0);
    if (status === 'sent') assert.equal(guidance[0], "Invitation sent. If the tester doesn't see it within a few minutes, ask them to check Spam or Promotions.");
    assert.equal(writes, 0);
  }
});
