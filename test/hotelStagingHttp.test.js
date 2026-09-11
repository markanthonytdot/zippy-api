const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {spawn} = require('node:child_process');
const path = require('node:path');
const {stayResult} = require('../test-support/hotelServerHarness');
const pause = ms => new Promise(r=>setTimeout(r,ms));
const listen = server => new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
const body = {city:'Miami',lat:25.76,lng:-80.19,checkIn:'2026-10-15',nights:5,adults:1,max:10};
async function fixture(t, env={}, mode='success') {
  const calls=[];let aborted=0;
  const provider=http.createServer(async(req,res)=>{
    let raw='';for await(const chunk of req)raw+=chunk;
    calls.push({path:req.url,body:raw?JSON.parse(raw):null});
    res.on('close',()=>{if(!res.writableEnded)aborted++});
    await pause(120);
    if(res.destroyed)return;
    res.setHeader('Content-Type','application/json');
    if(mode.startsWith('429')) {res.statusCode=429;if(mode==='429-retry')res.setHeader('Retry-After','3');res.end(JSON.stringify({error:'private fixture error'}));return;}
    const result=stayResult({check_out_date:'2026-10-20',guests:[{type:'adult'}]});
    res.end(JSON.stringify({data:req.url.includes('fetch_all_rates')?result:{results:[result]}}));
  });
  const providerPort=await listen(provider);
  const reservation=http.createServer();const port=await listen(reservation);await new Promise(r=>reservation.close(r));
  const child=spawn(process.execPath,['--require',path.join(__dirname,'../test-support/hotelStagingPreload.cjs'),path.join(__dirname,'../server.js')],{
    env:{PATH:process.env.PATH,NODE_ENV:'test',PORT:String(port),AUTH_MODE:'prod',JWT_SECRET:'fixture-only',DUFFEL_STAYS_KEY:'duffel_test_fixture',HOTEL_FIXTURE_ORIGIN:`http://127.0.0.1:${providerPort}`,FLIGHT_BOOKING_MODE:'disabled',HOTEL_TEST_BOOKING_ENABLED:'false',...env},stdio:'ignore'
  });
  t.after(async()=>{child.kill();await new Promise(r=>child.once('exit',r));provider.closeAllConnections();await new Promise(r=>provider.close(r));});
  const url=`http://127.0.0.1:${port}`;
  let ready=false;for(let i=0;i<100;i++){try{if((await fetch(url+'/health')).ok){ready=true;break;}}catch{}await pause(20);}
  assert(ready,'real server started');
  async function request(route='/v1/hotels/search', data=body, options={}) {
    const res=await fetch(url+route,{method:data===null?'GET':'POST',headers:{'Content-Type':'application/json',...options.headers},body:data===null?undefined:JSON.stringify(data),signal:options.signal});
    return {status:res.status,headers:Object.fromEntries(res.headers),body:await res.json()};
  }
  return {request,calls,aborted:()=>aborted};
}
for(const [window,env] of [['MINUTE',{HOTELS_RPM:'1'}],['HOUR',{HOTELS_HOURLY:'1'}],['DAY',{HOTELS_DAILY:'1'}]])test(`real HTTP ${window} exhaustion and accurate reset`,async t=>{
 const h=await fixture(t,env);assert.equal((await h.request()).status,200);const x=await h.request();assert.equal(x.status,429);
 const m=x.body.rateLimit;assert.equal(x.body.code,'HOTEL_RATE_LIMITED');assert.equal(m.window,window);assert.equal(m.source,'ZIPPI');assert.equal(m.limit,1);assert.equal(m.remaining,0);
 assert(Math.abs(Number(x.headers['retry-after'])-(Date.parse(m.resetAt)-Date.now())/1000)<2);assert.equal(h.calls.length,1);
 if(window!=='MINUTE'){const reset=new Date(m.resetAt);assert.equal(reset.getUTCMinutes(),0);if(window==='DAY')assert.equal(reset.getUTCHours(),0);}
 assert(!JSON.stringify(x).includes('duffel_test_fixture'));
});
test('real HTTP concurrent callers spend one provider debit and receive independent results',async t=>{
 const h=await fixture(t,{HOTELS_DAILY:'1'});assert.equal(h.calls.length,0);const [a,b]=await Promise.all([h.request(),h.request()]);assert.equal(a.status,200);assert.equal(b.status,200);assert.equal(h.calls.length,1);
 a.body.items[0].name='changed';assert.notEqual(b.body.items[0].name,'changed');const c=await h.request();assert.equal(c.status,429);assert.equal(c.body.rateLimit.window,'DAY');assert.equal(h.calls.length,1);
 t.diagnostic('provider counter: before=0 after concurrent pair=1 after rejected repeat=1');
});
for(const [label,patch,headers] of [['city',{city:'Bogota'},{}],['dates',{checkIn:'2026-10-16'},{}],['adults',{adults:2},{}],['access',{}, {'x-user-id':'different-device'}]])test(`real HTTP different ${label} requests do not coalesce`,async t=>{
 const h=await fixture(t);const results=await Promise.all([h.request(),h.request('/v1/hotels/search',{...body,...patch},{headers})]);assert(results.every(x=>x.status===200));assert.equal(h.calls.length,2);
});
test('real HTTP one cancellation leaves other caller alive; all cancellations clean up',async t=>{
 const h=await fixture(t);const a=new AbortController(),b=new AbortController();
 const first=h.request('/v1/hotels/search',body,{signal:a.signal}).catch(e=>e.name),second=h.request();
 while(h.calls.length<1)await pause(5);a.abort();assert.equal(await first,'AbortError');assert.equal((await second).status,200);assert.equal(h.aborted(),0);assert.equal(h.calls.length,1);
 const c=new AbortController();const p=h.request('/v1/hotels/search',body,{signal:b.signal}).catch(e=>e.name),q=h.request('/v1/hotels/search',body,{signal:c.signal}).catch(e=>e.name);
 while(h.calls.length<2)await pause(5);b.abort();c.abort();await Promise.all([p,q]);await pause(30);assert.equal(h.aborted(),1);
 assert.equal((await h.request()).status,200);assert.equal(h.calls.length,3);
});
test('real HTTP local photo/pricing cost zero; actual pricing shares provider budget',async t=>{
 const h=await fixture(t,{HOTELS_DAILY:'2'});
 assert.equal((await h.request('/v1/hotels/photo?hotelId=acc_fixture',null)).status,200);
 const pricing={hotelIds:['acc_fixture'],checkIn:'2026-10-15',nights:5,adults:1};
 assert.equal((await h.request('/v1/hotels/prices',pricing)).status,200);assert.equal(h.calls.length,0);
 assert.equal((await h.request('/v1/hotels/prices',{...pricing,searchResultIds:{acc_fixture:'srr_fixture'}})).status,200);assert.equal(h.calls.length,1);
 assert.equal((await h.request('/v1/hotels/prices',pricing)).status,200);assert.equal(h.calls.length,1);
 assert.equal((await h.request()).status,200);assert.equal(h.calls.length,2);assert.equal((await h.request()).body.rateLimit.scope,'PROVIDER_TOTAL');
 t.diagnostic('provider counter: local reads=0 actual pricing=1 cached pricing=1 discovery=2 blocked repeat=2');
});
test('real HTTP trusted QA finite; spoofed QA query/headers cannot bypass',async t=>{
 const h=await fixture(t,{HOTEL_TRAFFIC_CLASS:'QA',HOTELS_RPM:'1'});
 assert.equal((await h.request('/v1/hotels/ping',null)).status,200);
 const x=await h.request('/v1/hotels/ping?qa=true&bypass=true',null,{headers:{'x-qa':'true','x-internal-test':'true'}});assert.equal(x.status,429);assert.equal(x.body.rateLimit.scope,'API');assert.equal(h.calls.length,0);
});
for(const mode of ['429-retry','429-absent'])test(`real HTTP ${mode} uses provider source and only genuine cooldown`,async t=>{
 const h=await fixture(t,{},mode);const x=await h.request();assert.equal(x.status,429);assert.equal(x.body.rateLimit.source,'PROVIDER');assert.equal(x.headers['retry-after'],mode==='429-retry'?'3':undefined);
 if(mode==='429-absent')assert.equal(x.body.rateLimit.resetAt,undefined);assert(!JSON.stringify(x).includes('private fixture error'));
});
