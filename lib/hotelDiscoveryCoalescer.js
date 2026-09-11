function abortError() { const e = new Error('Hotel caller cancelled'); e.name = 'AbortError'; e.code = 'HOTEL_CALLER_CANCELLED'; return e; }
// Only concurrent work is shared. There is intentionally no completed-result cache.
function createHotelDiscoveryCoalescer() {
  const active = new Map();
  return {
    size: () => active.size,
    run(key, signal, work) {
      if (signal?.aborted) return Promise.reject(abortError());
      let entry = active.get(key);
      if (!entry) {
        entry = { controller: new AbortController(), callers: 0, settled: false };
        active.set(key, entry);
        entry.promise = Promise.resolve().then(() => {
          if (entry.controller.signal.aborted) throw abortError();
          return work(entry.controller.signal);
        }).finally(() => { entry.settled = true; if (active.get(key) === entry) active.delete(key); });
      }
      entry.callers++;
      return new Promise((resolve,reject) => {
        let done = false;
        const finish = (fn,value) => {
          if (done) return; done = true; signal?.removeEventListener('abort',cancel); entry.callers--;
          if (!entry.callers && !entry.settled) { if (active.get(key) === entry) active.delete(key); entry.controller.abort(); }
          fn(value);
        };
        const cancel = () => finish(reject,abortError());
        signal?.addEventListener('abort',cancel,{ once:true });
        if (signal?.aborted) cancel();
        entry.promise.then(value => finish(resolve,value),error => finish(reject,error));
      });
    },
  };
}
module.exports = { createHotelDiscoveryCoalescer, abortError };
