const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createHotelReadReliability } = require('../lib/hotelReadReliability');
const tick = () => new Promise(resolve => setImmediate(resolve));
const options = token => ({ method: 'POST', headers: { Authorization: token, 'Duffel-Version': 'v2' }, body: '{}' });
function caller(service, token = 'fixture', timeout = 1000) {
  const req = new EventEmitter();
  const res = Object.assign(new EventEmitter(), {
    headers: {}, setHeader(k,v) { this.headers[k] = v; },
    status(n) { this.statusCode = n; return this; }, json(value) { this.value = value; },
  });
  const promise = service.route(async () => service.fetch('https://provider.invalid/search', options(token), timeout, 'DISCOVERY'))(req,res);
  return { req, res, promise };
}
function service(fetch) { return createHotelReadReliability({env:{},identity:()=> 'same-account',fetch}); }
function response(text = '{}') { return {ok:true,status:200,headers:new Headers(),text:async()=>text}; }
test('different provider credentials never share a discovery operation', async () => {
  let count=0, release;
  const wait = new Promise(resolve => release=resolve);
  const s=service(async()=>{count++;await wait;return response();});
  const a=caller(s,'provider-a'),b=caller(s,'provider-b');
  await tick();assert.equal(count,2);release();await Promise.all([a.promise,b.promise]);
});
test('all callers cancelling aborts upstream and removes route listeners', async () => {
  let signal;
  const s=service((_url,opts)=>new Promise((_resolve,reject)=>{
    signal=opts.signal;signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true});
  }));
  const a=caller(s),b=caller(s);await tick();a.req.emit('aborted');assert.equal(signal.aborted,false);
  b.req.emit('aborted');await Promise.all([a.promise,b.promise]);assert.equal(signal.aborted,true);
  for(const c of [a,b]) {assert.equal(c.req.listenerCount('aborted'),0);assert.equal(c.res.listenerCount('close'),0);assert.equal(c.res.value,undefined);}
});
test('production header-only timeout preserves slow body and coalesces callers', async () => {
  let count=0, signal, finish;
  const body=new Promise(resolve=>finish=resolve);
  const s=service(async(_url,opts)=>{
    count++; signal=opts.signal;
    return {...response(),text:async()=>body};
  });
  const a=caller(s,'fixture',20),b=caller(s,'fixture',20);
  await new Promise(resolve=>setTimeout(resolve,60));
  assert.equal(signal.aborted,false);assert.equal(count,1);
  finish('{}'); await Promise.all([a.promise,b.promise]);
  await caller(s).promise;assert.equal(count,2);
});
test('production header timeout still aborts without retry', async () => {
  let count=0;
  const s=service((_url,opts)=>new Promise((_resolve,reject)=>{
    count++;opts.signal.addEventListener('abort',()=>reject(new Error('headers timeout')),{once:true});
  }));
  const a=caller(s,'fixture',20),b=caller(s,'fixture',20);
  const results=await Promise.allSettled([a.promise,b.promise]);
  assert(results.every(r=>r.status==='rejected'&&r.reason.message==='headers timeout'));
  assert.equal(count,1);
});
test('failed provider body cancellation cannot mask genuine HTTP 429', async () => {
  const s=service(async()=>({...response(),status:429,headers:new Headers({'retry-after':'3'}),body:{cancel:async()=>{throw new Error('secret cleanup detail');}}}));
  const c=caller(s);await c.promise;assert.equal(c.res.statusCode,429);
  assert.equal(c.res.value.rateLimit.source,'PROVIDER');assert.equal(c.res.headers['Retry-After'],'3');
  assert(!JSON.stringify(c.res).includes('secret cleanup detail'));
});
