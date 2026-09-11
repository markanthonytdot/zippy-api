const { AsyncLocalStorage } = require('node:async_hooks');
const { createHash } = require('node:crypto');
const { createHotelReadBudget } = require('./hotelReadBudget');
const { createHotelDiscoveryCoalescer, abortError } = require('./hotelDiscoveryCoalescer');
const { HotelRateLimitError, sendHotelRateLimit, providerLimit } = require('./hotelRateLimit');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function createHotelReadReliability({ env = process.env, now = Date.now, fetch, identity } = {}) {
  const context = new AsyncLocalStorage(); const budget = createHotelReadBudget({env,now});
  const coalescer = createHotelDiscoveryCoalescer();
  return {
    api(req,res,next) { try { budget.api(identity(req)); return next(); } catch(e) { if(e instanceof HotelRateLimitError) return sendHotelRateLimit(res,e); throw e; } },
    route(handler) {
      return async (req,res,next) => {
        const controller = new AbortController();
        const abort = () => controller.abort();
        const close = () => { if (!res.writableEnded) abort(); };
        req.once?.('aborted',abort); res.once?.('close',close);
        if (req.aborted || res.destroyed) abort();
        try { return await context.run({ identity:identity(req), signal:controller.signal }, () => handler(req,res,next)); }
        catch(e) { if (controller.signal.aborted) return; if (e instanceof HotelRateLimitError) return sendHotelRateLimit(res,e); throw e; }
        finally { req.removeListener?.('aborted',abort); res.removeListener?.('close',close); }
      };
    },
    async fetch(url, options, timeoutMs, operation, facts = {}) {
      const caller = context.getStore();
      if (!caller) throw new Error('Hotel read requires an owned request');
      const provider = digest(options.headers?.Authorization);
      const run = async signal => {
        if (signal.aborted) throw abortError();
        budget.provider(caller.identity,provider,operation);
        const controller = new AbortController();
        const abort = () => controller.abort(); signal.addEventListener('abort',abort,{once:true});
        const timer = setTimeout(abort,timeoutMs);
        try {
          if(signal.aborted) abort();
          const response = await fetch(url,{...options,signal:controller.signal});
          if(response.status === 429) {
            const error = providerLimit(response.headers,operation,now());
            try { await response.body?.cancel?.(); } finally { throw error; }
          }
          const raw = await response.text();
          return {ok:response.ok,status:response.status,headers:response.headers,text:async()=>raw};
        } catch (error) { if (signal.aborted) throw abortError(); throw error; }
        finally { clearTimeout(timer); signal.removeEventListener('abort',abort); }
      };
      if(operation !== 'DISCOVERY') return run(caller.signal);
      // Same access identity only; no sharing private or negotiated inventory across callers.
      const key = digest([budget.traffic,caller.identity,provider,url,options.method,options.headers,JSON.parse(options.body),facts]);
      return coalescer.run(key,caller.signal,run);
    },
  };
}
module.exports = { createHotelReadReliability };
