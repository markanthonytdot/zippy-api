// Existing admin-authorized pending workflows only; the service never enrolls
// or notifies Apple from this worker. Database state survives restarts/spin-down.
function startTesterInvitationWorker(service, { setIntervalImpl = setInterval } = {}) {
  const tick = () => service.reconcilePending().catch(() => {});
  const timer = setIntervalImpl(tick, 60000);
  timer.unref?.();
  void tick();
  return timer;
}
module.exports = { startTesterInvitationWorker };
