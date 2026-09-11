const test = require('node:test');
const assert = require('node:assert/strict');
const { startTesterInvitationWorker } = require('../lib/testerInvitationWorker');
test('worker reconciles on startup and every minute without retaining a process or leaking failures', async () => {
  let callback, ticks = 0, unrefs = 0;
  startTesterInvitationWorker({ async reconcilePending() { ticks++; throw new Error('private failure'); } }, {
    setIntervalImpl(fn, delay) { callback = fn; assert.equal(delay, 60000); return { unref() { unrefs++; } }; },
  });
  await callback(); assert.equal(ticks, 2); assert.equal(unrefs, 1);
});
