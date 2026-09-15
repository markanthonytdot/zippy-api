const test=require('node:test');
const assert=require('node:assert/strict');
const {once}=require('node:events');
const express=require('express');
const {createFeedbackAdminRemote,feedbackNavigation}=require('../lib/feedbackAdminRemote');
const {createAdminSessionToken,ADMIN_COOKIE}=require('../lib/adminDashboard');
const {sharedAdminFixture}=require('./helpers/sharedAdminFixture');
const configured=!!(process.env.FEEDBACK_API_TEST_ROOT&&process.env.FEEDBACK_AUTH_TEST_DATABASE_URL);
const pages=['/admin/','/admin/partner-access','/admin/demo-feedback','/admin/package-feedback'];
const reads=['/admin/api/partner-access','/admin/api/android-testers','/admin/api/demo-feedback','/admin/api/package-feedback','/admin/api/demo-feedback/export.csv','/admin/api/package-feedback/export.csv'];

test('one unchanged tester-admin login covers testers, feedback, exports and logout',{skip:!configured},async t=>{
 const f=await sharedAdminFixture();t.after(()=>f.close());
 const request=(p,options={})=>fetch(f.base+p,{redirect:'manual',...options});
 for(const page of pages){const r=await request(page);assert.equal(r.status,302);assert.equal(r.headers.get('location'),'/admin/login');}
 for(const p of reads)assert.equal((await request(p)).status,401);
 assert.equal(f.forwarded.length,0);
 let r=await request('/admin/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'secret=incorrect-local-password'});assert.equal(r.status,401);
 r=await request('/admin/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({secret:f.adminPassword})});assert.equal(r.status,303);
 const setCookie=r.headers.get('set-cookie');for(const flag of ['HttpOnly','Secure','SameSite=Strict','Path=/admin'])assert.ok(setCookie.includes(flag));
 const cookie=setCookie.split(';')[0];const headers={Cookie:cookie};
 for(const page of pages){const result=await request(page,{headers});assert.equal(result.status,200);const html=await result.text();assert.ok(html.includes('Feedback</p>'));assert.equal((html.match(/href="\/admin\/demo-feedback"/g)||[]).length,1);assert.equal((html.match(/href="\/admin\/package-feedback"/g)||[]).length,1);assert.ok(!html.includes(f.secret));assert.ok(!html.includes('http://127.0.0.1'));}
 for(const p of reads)assert.equal((await request(p,{headers})).status,200);
 // A session issued by the unchanged pre-feature login contract is still accepted.
 const existing=`${ADMIN_COOKIE}=${createAdminSessionToken(f.sessionSecret,Date.now()-60000)}`;
 for(const p of reads)assert.equal((await request(p,{headers:{Cookie:existing}})).status,200);
 for(const value of [cookie+'tampered',`${ADMIN_COOKIE}=${createAdminSessionToken(f.sessionSecret,Date.now()-9*60*60*1000)}`,`${ADMIN_COOKIE}=${createAdminSessionToken('different-environment-signing-key')}`])for(const p of reads)assert.equal((await request(p,{headers:{Cookie:value}})).status,401);
 const flight=await (await request('/admin/api/demo-feedback?source=test',{headers})).json();assert.equal(flight.overall.total,1);assert.equal(flight.overall.comprehension.correct.percent,100);
 const pack=await (await request('/admin/api/package-feedback?source=test',{headers})).json();assert.equal(pack.overall.total,1);assert.equal(pack.funnel.flightCompleted,1);assert.equal(pack.funnel.packageClicks,1);assert.equal(pack.funnel.fromFlightSubmitted,0);
 for(const name of ['demo-feedback','package-feedback']){
  const csv=await request('/admin/api/'+name+'/export.csv?source=test',{headers});const body=await csv.text();assert.equal(csv.status,200);assert.ok(body.includes('"test"'));assert.ok(!body.includes('local-other'));assert.ok(body.includes("'=LOCAL_FORMULA"));assert.equal(csv.headers.get('cache-control'),'no-store');
  const empty=await (await request('/admin/api/'+name+'/export.csv?likelihood=Definitely%20not',{headers})).text();assert.equal(empty.trim().split('\r\n').length,1);
  assert.equal((await request('/admin/api/'+name+'?source=bad%40email',{headers})).status,400);
  assert.equal((await request('/admin/api/'+name+'?url=https://untrusted.example',{headers})).status,400);
  assert.equal((await request('/admin/api/'+name,{method:'POST',headers})).status,405);
 }
 // The read-only proxy must not intercept or weaken existing tester mutations.
 const writeHeaders={...headers,'Content-Type':'application/json',Origin:f.base};
 assert.equal((await request('/admin/api/android-testers',{method:'POST',headers:writeHeaders,body:'{"action":"prepare"}'})).status,200);
 assert.equal((await request('/admin/api/partner-access/organizations',{method:'POST',headers:writeHeaders,body:'{"name":"Local fixture"}'})).status,201);
 assert.deepEqual(f.testerWrites,['android','ios']);
 assert.equal((await request('/admin/api/android-testers',{method:'POST',headers:{...writeHeaders,Origin:'https://untrusted.example'},body:'{}'})).status,403);
 assert.ok(f.forwarded.every(call=>call.method==='GET'&&call.redirect==='error'&&call.headerNames.join(',')==='x-zippi-feedback-read'));
 r=await request('/admin/logout',{method:'POST',headers});assert.equal(r.status,303);assert.ok(r.headers.get('set-cookie').includes(`${ADMIN_COOKIE}=;`));assert.ok(r.headers.get('set-cookie').includes('Path=/admin'));
 // Apply the browser's cookie deletion; logout does not change the pre-existing stateless session design.
 for(const p of reads)assert.equal((await request(p)).status,401);
 for(const p of pages)assert.equal((await request(p)).status,302);
});

test('remote transport fails closed on upstream auth/error/redirect/content failures without leaking secrets',async t=>{
 let mode='401';let calls=0;const secret='local-only-feedback-read-test-credential';
 const remote=createFeedbackAdminRemote({secret,fetchImpl:async(_url,options)=>{calls++;assert.equal(options.redirect,'error');if(mode==='throw')throw new Error(secret);return new Response(mode==='badtype'?'private internal html':'private upstream error '+secret,{status:mode==='badtype'?200:Number(mode),headers:{'Content-Type':mode==='badtype'?'text/html':'text/plain'}});}});
 const app=express();app.use((req,_res,next)=>{if(req.get('x-local-fixture-admin')==='yes')req.zippiAdmin={actor:'local-fixture'};next();});app.use('/api',remote.router);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{server.closeAllConnections();return new Promise(r=>server.close(r));});const base=`http://127.0.0.1:${server.address().port}`;
 assert.equal((await fetch(base+'/api/demo-feedback')).status,401);assert.equal(calls,0);
 for(mode of ['401','403','500','302','badtype','throw']){const r=await fetch(base+'/api/demo-feedback',{headers:{'x-local-fixture-admin':'yes'}});assert.equal(r.status,503);assert.deepEqual(await r.json(),{ok:false,error:'feedback_unavailable'});}
});
test('feedback navigation separates current and historical pages with native same-host links',()=>{
 const html=feedbackNavigation('<aside class="sidebar"><nav><p class="nav-label">Business</p><a href="/admin/demo-feedback">Old</a></nav></aside>','package-feedback');
 assert.match(html,/Feedback<\/p>/);assert.match(html,/>Demo feedback</);assert.match(html,/>Package feedback \(historical\)</);assert.equal((html.match(/aria-current="page"/g)||[]).length,1);assert.equal((html.match(/href="\/admin\/demo-feedback"/g)||[]).length,1);assert.ok(!html.includes('https:'));
 const historical=feedbackNavigation('<title>Package demo feedback · Zippi Admin</title><h1>Package demo feedback</h1>','package-feedback');assert.match(historical,/<h1>Historical package demo feedback<\/h1>/);
});

test('remote reports and CSV preserve explicit current and historical survey filters',async t=>{
 const forwarded=[];
 const remote=createFeedbackAdminRemote({secret:'local-only-feedback-read-test-credential',fetchImpl:async(url,options)=>{
  forwarded.push({url,options});
  return new Response(url.includes('export.csv')?'survey_version\r\ncombined_demo_v3':JSON.stringify({ok:true}),{headers:{'Content-Type':url.includes('export.csv')?'text/csv':'application/json'}});
 }});
 const app=express();app.use((req,_res,next)=>{req.zippiAdmin={actor:'local-test'};next();});app.use('/api',remote.router);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{server.closeAllConnections();return new Promise(r=>server.close(r));});
 const base=`http://127.0.0.1:${server.address().port}`;
 for(const route of ['demo-feedback','demo-feedback/export.csv']){
  const query=new URLSearchParams({survey_version:'combined_demo_v3',clarity:'Very clear',booked:'yes',likelihood:'Probably',source:'family'});
  const response=await fetch(`${base}/api/${route}?${query}`);assert.equal(response.status,200);await response.text();
  const passed=new URL(forwarded.at(-1).url);assert.equal(passed.searchParams.get('survey_version'),'combined_demo_v3');assert.equal(passed.searchParams.get('clarity'),'Very clear');assert.equal(passed.searchParams.get('booked'),'yes');
 }
 for(const survey of ['free_text_v1','multiple_choice_v2'])assert.equal((await fetch(`${base}/api/demo-feedback?survey_version=${survey}`)).status,200);
 assert.equal((await fetch(base+'/api/demo-feedback')).status,200);assert.equal(new URL(forwarded.at(-1).url).searchParams.has('survey_version'),false);
 assert.equal((await fetch(base+'/api/demo-feedback?endpoint=untrusted')).status,400);
 assert.ok(forwarded.every(call=>Object.keys(call.options.headers).join(',')==='x-zippi-feedback-read'));
});
