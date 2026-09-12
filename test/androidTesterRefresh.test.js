const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../admin/public/tester-access-duration.js'), 'utf8') + '\n' + fs.readFileSync(require.resolve('../admin/public/android-testers.js'), 'utf8');

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
  form.elements = { platform: { value: 'android' }, email: { value: 'refresh-fixture@heyzippi.test' }, durationDays: Object.assign(new Element('select'), {value:'7'}), customDurationDays: Object.assign(new Element('input'), {value:''}) };
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
    invitations: [{ id: '00000000-0000-4000-8000-000000000001', email: 'refresh-fixture@heyzippi.test', access: 'active', expiresAt: '2026-09-19T12:00:00Z',
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

test('new tester duration selector sends exactly one prepare with each chosen fixed duration', async () => {
  for (const days of [1, 3, 7, 14, 30]) {
    const writes = [];
    const app = ui(async (_url, options) => {
      if (options.method === 'POST') { writes.push(JSON.parse(options.body)); return response({invitation: result().invitations[0]}); }
      return response(result());
    });
    await tick(); app.form.elements.durationDays.value = String(days); await app.form.fire('submit'); await tick();
    assert.equal(writes.length, 1); assert.equal(writes[0].action, 'prepare'); assert.equal(writes[0].durationDays, days);
    const expiry = app.get('android-tester-rows').children[0].children.find(e => e.textContent.startsWith('Expires:'));
    assert.ok(expiry); assert.ok(!expiry.textContent.includes('Not available'));
  }
});
test('changing duration and refreshing never modifies existing access; explicit extension requires confirmation', async () => {
  const writes = []; const app = ui(async (_url, options) => {
    if (options.method === 'POST') { writes.push(JSON.parse(options.body)); return response({invitation: result().invitations[0]}); }
    return response(result());
  });
  await tick(); app.form.elements.durationDays.value = '1'; await app.form.fire('change'); await app.refresh();
  assert.equal(writes.length, 0);
  const nodes = parent => parent.children.flatMap(child=>[child,...nodes(child)]);
  const pending = app.button('Extend access').fire('click');
  const current = nodes(app.body); assert.ok(current.some(e=>e.textContent.startsWith('Current expiry:')));
  const select = current.find(e=>e.tag==='select'); select.value='3';
  await current.find(e=>e.tag==='button' && e.textContent==='Extend access').fire('click'); await pending;
  assert.equal(writes.length, 1); assert.equal(writes[0].action,'extend'); assert.equal(writes[0].durationDays,3);
  assert.equal(writes[0].expectedExpiresAt,result().invitations[0].expiresAt); assert.equal(writes[0].confirm,true);
  const cancel = app.button('Extend access').fire('click');
  await nodes(app.body).find(e=>e.tag==='button' && e.textContent==='Cancel').fire('click'); await cancel;
  assert.equal(writes.length,1);
});
test('expired revoked and disabled states stay separate and do not enable Send', async () => {
  for (const access of ['expired','revoked','disabled']) {
    const data=result('confirmed');data.invitations[0].access=access;
    const app=ui(async()=>response(data));await tick();
    const texts=app.get('android-tester-rows').children[0].children.map(e=>e.textContent);
    assert.ok(texts.includes(`Zippi access: ${access[0].toUpperCase()+access.slice(1)}`));
    assert.equal(app.button('Send Android invitation').disabled,true);
  }
});

test('Custom prepare rejects every invalid input inline without mutation then accepts 2/5/10/90', async () => {
  const writes=[];const app=ui(async(_url, options)=>{
    if(options.method==='POST'){writes.push(JSON.parse(options.body));return response({invitation:result().invitations[0]});}
    return response(result());
  });
  await tick();const select=app.form.elements.durationDays;const input=app.form.elements.customDurationDays;
  assert.equal(input.disabled,true);select.value='custom';await select.fire('change');
  assert.equal(input.disabled,false);assert.equal(input.required,true);assert.equal(app.get('tester-custom-days-label').hidden,false);
  for(const raw of ['','0','-1','1.5','91','abc','1e1']) {
    input.value=raw;await app.form.fire('submit');await tick();
    assert.equal(writes.length,0);assert.match(app.get('tester-duration-error').textContent,/whole number.*1 to 90/);
  }
  for(const value of [2,5,10,90]) {
    input.value=String(value);await input.fire('input');assert.equal(app.get('tester-duration-error').textContent,'');
    await app.form.fire('submit');await tick();assert.equal(writes.at(-1).durationDays,value);
  }
  select.value='7';await select.fire('change');assert.equal(input.disabled,true);assert.equal(input.required,false);
  assert.equal(app.get('tester-custom-days-label').hidden,true);assert.equal(writes.length,4);
});
test('Custom Extend stays open on invalid input and submits once with stored expiry guard', async () => {
  const writes=[];const app=ui(async(_url,options)=>{
    if(options.method==='POST'){writes.push(JSON.parse(options.body));return response({invitation:result().invitations[0]});}
    return response(result());
  });await tick();const pending=app.button('Extend access').fire('click');
  const descendants=e=>e.children.flatMap(c=>[c,...descendants(c)]);const nodes=descendants(app.body);
  const select=nodes.find(e=>e.tag==='select'),input=nodes.find(e=>e.tag==='input');
  const confirm=nodes.find(e=>e.tag==='button'&&e.textContent==='Extend access');
  select.value='custom';await select.fire('change');input.value='91';await confirm.fire('click');
  assert.equal(writes.length,0);assert.ok(nodes.some(e=>e.textContent.includes('whole number')));
  input.value='5';await input.fire('input');await confirm.fire('click');await pending;
  assert.equal(writes.length,1);assert.equal(writes[0].durationDays,5);assert.equal(writes[0].expectedExpiresAt,result().invitations[0].expiresAt);
});
