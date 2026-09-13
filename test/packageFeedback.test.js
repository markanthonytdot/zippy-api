const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {once}=require('node:events');
const {createPackageFeedbackService,validatePackageSubmission,validatePackageClick,parsePackageFilters,packageFilterSql,summarizePackages,packageFunnel,packageCsvLine,CSV_HEADERS}=require('../lib/packageFeedback');
const {installPackageFeedbackRuntime,createPackageFeedbackAdminRouter}=require('../lib/packageFeedbackRoutes');
const {createDemoFeedbackService}=require('../lib/demoFeedback');
const {createDemoFeedbackPublicRouter}=require('../lib/demoFeedbackRoutes');
const {createAdminDashboardRouter,createAdminSessionToken,ADMIN_COOKIE}=require('../lib/adminDashboard');
const answer=(extra={})=>({request_id:crypto.randomUUID(),demo_type:'package',likelihood:'Definitely',usefulness:'Yes',comment:'',source:'reddit',entry_path:'direct',...extra});
const click=(extra={})=>({event_id:crypto.randomUUID(),source:'reddit',entry_path:'flight_thank_you',...extra});

test('package validates exact required choices, optional comments, source and entry paths',()=>{
  for(const likelihood of ['Definitely','Probably','Probably not','Definitely not']) for(const usefulness of ['Yes','No','Not sure']) for(const entry_path of ['direct','flight_thank_you']) {
    const value=validatePackageSubmission(answer({likelihood,usefulness,entry_path}));assert.equal(value.likelihood,likelihood);assert.equal(value.usefulness,usefulness);assert.equal(value.entry_path,entry_path);
  }
  for(const comment of [undefined,null,'','  ']) assert.equal(validatePackageSubmission(answer({comment})).comment,'');
  assert.equal(validatePackageSubmission(answer({comment:'  Helpful.  '})).comment,'Helpful.');
  const defaults=validatePackageSubmission(answer({source:undefined,entry_path:undefined,demo_type:undefined}));assert.equal(defaults.source,'direct');assert.equal(defaults.entry_path,'direct');assert.equal(defaults.demo_type,'package');
  for(const extra of [{likelihood:undefined},{likelihood:null},{likelihood:'Maybe'},{likelihood:['Probably']},{usefulness:undefined},{usefulness:'yes'},{usefulness:['Yes']},{entry_path:''},{entry_path:null},{entry_path:'email'},{entry_path:['direct']},{source:'person@example.com'},{source:'x'.repeat(65)},{source:'https://example.com'},{source:null},{source:['reddit']},{comment:2},{comment:'a'.repeat(2001)},{comment:'a\0b'},{request_id:'bad'},{demo_type:'flight'},{website:'bot'}]) assert.throws(()=>validatePackageSubmission(answer(extra)),e=>e.status===400);
  for(const value of [null,[],false]) assert.throws(()=>validatePackageSubmission(value));
});
test('anonymous click validation accepts only flight thank-you attribution',()=>{
  assert.equal(validatePackageClick(click()).source,'reddit');assert.equal(validatePackageClick(click({source:undefined})).source,'direct');
  for(const extra of [{event_id:undefined},{event_id:'bad'},{entry_path:undefined},{entry_path:'direct'},{source:'<script>'},{website:'bot'}]) assert.throws(()=>validatePackageClick(click(extra)),e=>e.status===400);
});
test('package filters bind values; funnel deliberately uses only source and date',()=>{
  const filters=parsePackageFilters({source:'reddit',likelihood:'Probably',usefulness:'Yes',entry_path:'flight_thank_you',from:'2026-09-01',to:'2026-09-13',page:'2'});
  assert.equal(filters.page,2);
  assert.deepEqual(packageFilterSql(filters).params,['reddit','Probably','Yes','flight_thank_you','2026-09-01T00:00:00Z','2026-09-14T00:00:00.000Z']);
  assert.deepEqual(packageFilterSql(filters,{funnel:true,timeColumn:'created_at'}),{where:'where source = $1 and created_at >= $2::timestamptz and created_at < $3::timestamptz',params:['reddit','2026-09-01T00:00:00Z','2026-09-14T00:00:00.000Z']});
  for(const query of [{source:"x' or 1=1"},{usefulness:'Maybe'},{entry_path:'injected'},{entry_path:['direct']},{from:'2026-02-30'},{from:'2026-09-14',to:'2026-09-13'},{sort:'drop table'},{page:'0'}]) assert.throws(()=>parsePackageFilters(query),e=>e.status===400);
});
test('package summaries and anonymous funnel have correct distinct denominators',()=>{
  const data=summarizePackages([
    {source:'reddit',likelihood:'Definitely',usefulness:'Yes',entry_path:'flight_thank_you',count:'2'},
    {source:'reddit',likelihood:'Probably',usefulness:'Not sure',entry_path:'direct',count:1},
    {source:'family',likelihood:'Probably not',usefulness:'No',entry_path:'direct',count:1},
    {source:'direct',likelihood:'Definitely not',usefulness:'No',entry_path:'direct',count:1}]);
  assert.equal(data.overall.total,5);assert.equal(data.overall.positive.percent,60);assert.equal(data.overall.usefulness.Yes.percent,40);assert.equal(data.overall.entryPaths.direct.percent,60);assert.equal(data.sources[0].positive.percent,100);
  assert.equal(summarizePackages([]).overall.positive.percent,0);
  assert.deepEqual(packageFunnel(10,4,3),{flightCompleted:10,packageClicks:4,fromFlightSubmitted:3,clickThroughPercent:40,completionAfterClickPercent:75});
  assert.equal(packageFunnel(0,0,0).clickThroughPercent,null);assert.equal(packageFunnel(0,0,0).completionAfterClickPercent,null);assert.equal(packageFunnel(1,2,3).completionAfterClickPercent,150);
});
test('package CSV uses separate fields and shared formula protection',()=>{
  assert.equal(CSV_HEADERS.length,8);
  const line=packageCsvLine({id:'row',demo_type:'package',submitted_at:new Date('2026-09-13T12:00Z'),source:'reddit',entry_path:'direct',likelihood:'Probably',usefulness:'Yes',comment:'Flights, "hotel"\ntogether.'});
  assert.ok(line.includes('"Flights, ""hotel""\ntogether."'));assert.ok(line.includes('"package"'));assert.ok(line.includes('2026-09-13T12:00:00.000Z'));
  for(const prefix of ['=','+','-','@','\t=',' \n=']) assert.ok(packageCsvLine({comment:prefix+'formula'}).includes('"\''));
});
test('package rollout flag leaves existing app untouched when disabled',()=>{
  const calls=[];const app={use:(...args)=>calls.push(args)};
  assert.equal(installPackageFeedbackRuntime(app,{environment:{}}),null);assert.equal(calls.length,0);
  assert.ok(installPackageFeedbackRuntime(app,{secret:'test',environment:{ZIPPI_PACKAGE_FEEDBACK_ENABLED:'true'}}));assert.deepEqual(calls.map(x=>x[0]),['/v1/package-feedback/events','/v1/package-feedback']);
});

const databaseUrl=process.env.PACKAGE_FEEDBACK_TEST_DATABASE_URL;
test('package real PostgreSQL, HTTP, protected admin and flight isolation',{skip:!databaseUrl},async t=>{
  const url=new URL(databaseUrl);assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname));
  const {Pool}=require('pg');const express=require('express');
  const schema=`package_feedback_${crypto.randomBytes(8).toString('hex')}`;
  const root=new Pool({connectionString:databaseUrl,ssl:false});await root.query(`create schema ${schema}`);
  const pool=new Pool({connectionString:databaseUrl,ssl:false,options:`-c search_path=${schema}`});
  for(const file of ['016_demo_feedback.sql','017_demo_feedback_comprehension.sql','018_package_demo_feedback.sql']) await pool.query(fs.readFileSync(path.join(__dirname,'../migrations',file),'utf8'));
  let clock=Date.now();const service=createPackageFeedbackService({dbPool:pool,secret:'test-package-secret',now:()=>clock});
  const flight=createDemoFeedbackService({dbPool:pool,secret:'test-flight-secret',now:()=>clock});
  await flight.submit({request_id:crypto.randomUUID(),comprehension_choice:'natural_language_flight_search',likelihood:'Probably',recent_flight_shopper:true,source:'reddit'},'flight-seed');
  const flightBefore=await flight.report({});const flightRows=(await pool.query('select * from demo_feedback_responses')).rows;
  const app=express();app.use(express.json({limit:'8kb'}));app.use(express.urlencoded({extended:false}));
  app.use('/v1/demo-feedback',createDemoFeedbackPublicRouter({service:flight}));
  app.use('/v1/package-feedback/events',createDemoFeedbackPublicRouter({service:{submit:service.recordClick},allowedOrigins:'http://localhost:4173'}));
  app.use('/v1/package-feedback',createDemoFeedbackPublicRouter({service,allowedOrigins:'http://localhost:4173'}));
  app.use('/admin',createAdminDashboardRouter({dbPool:pool,adminSecret:'package-admin-test',sessionSecret:'package-session-test',demoFeedbackService:flight,packageFeedbackService:service}));
  const server=app.listen(0,'127.0.0.1');await once(server,'listening');const base=`http://127.0.0.1:${server.address().port}`;
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));await pool.end();await root.query(`drop schema ${schema} cascade`);await root.end();});
  const post=(body,route='/v1/package-feedback')=>fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json',Origin:'http://localhost:4173'},body:JSON.stringify(body)});
  let cookie;
  await t.test('direct and flight entries persist separately; retry deduplicates and changed retry conflicts',async()=>{
    const body=answer({entry_path:'flight_thank_you',comment:'Flights, "hotel"\ntogether.'});
    let response=await post(body);assert.equal(response.status,201);assert.deepEqual(await response.json(),{ok:true});assert.equal(response.headers.get('cache-control'),'no-store');
    assert.equal((await post(body)).status,201);assert.equal((await post({...body,usefulness:'No'})).status,409);
    assert.equal((await post(answer({source:undefined,entry_path:undefined,likelihood:'Probably',usefulness:'Not sure',comment:undefined}))).status,201);
    const rows=(await pool.query('select * from package_feedback_responses order by submitted_at')).rows;assert.equal(rows.length,2);assert.equal(rows[0].entry_path,'flight_thank_you');assert.equal(rows[0].source,'reddit');assert.equal(rows[1].source,'direct');assert.equal(rows[1].entry_path,'direct');assert.equal(rows[1].comment,'');assert.ok(rows[0].id);assert.equal(rows[0].demo_type,'package');
    assert.equal((await pool.query('select count(*) from package_feedback_clicks')).rows[0].count,'0','Submitting either poll must not create a click');
  });
  await t.test('click is anonymous, idempotent, separate from submissions and source validated',async()=>{
    const body=click();assert.equal((await post(body,'/v1/package-feedback/events')).status,201);assert.equal((await post(body,'/v1/package-feedback/events')).status,201);assert.equal((await post({...body,source:'family'},'/v1/package-feedback/events')).status,409);
    assert.equal((await post(click({entry_path:'direct'}),'/v1/package-feedback/events')).status,400);
    const rows=(await pool.query('select * from package_feedback_clicks')).rows;assert.equal(rows.length,1);assert.deepEqual(Object.keys(rows[0]).sort(),['created_at','event_id','event_type','source']);assert.equal(rows[0].source,'reddit');
  });
  await t.test('invalid payloads never insert; JSON type and request limits enforced',async()=>{
    clock+=16*60*1000;
    for(const extra of [{likelihood:undefined},{usefulness:undefined},{source:'bad@email.test'},{entry_path:'bad'},{comment:123},{website:'spam'}]) assert.equal((await post(answer(extra))).status,400);
    assert.equal((await pool.query('select count(*) from package_feedback_responses')).rows[0].count,'2');
    assert.equal((await fetch(base+'/v1/package-feedback',{method:'POST',headers:{'Content-Type':'text/plain'},body:'bad'})).status,415);
    assert.equal((await post(answer({comment:'x'.repeat(9000)}))).status,413);
  });
  await t.test('public reads, exports, metrics, admin pages and assets are protected',async()=>{
    for(const route of ['/v1/package-feedback','/v1/package-feedback/events','/v1/package-feedback/summary','/v1/package-feedback/export.csv']) assert.equal((await fetch(base+route)).status,405);
    for(const route of ['/admin/api/package-feedback','/admin/api/package-feedback/export.csv']) {const response=await fetch(base+route);assert.equal(response.status,401);assert.equal(response.headers.get('cache-control'),'no-store');}
    for(const route of ['/admin/package-feedback','/admin/assets/package-feedback.js','/admin/assets/package-feedback.css']) {const response=await fetch(base+route,{redirect:'manual'});assert.equal(response.status,302);assert.equal(response.headers.get('location'),'/admin/login');}
    for(const route of ['/v1/package-feedback','/v1/package-feedback/events']) {
      assert.equal((await fetch(base+route,{method:'POST',headers:{Origin:'https://evil.test','Content-Type':'application/json'},body:JSON.stringify(answer())})).status,403);
      assert.equal((await fetch(base+route,{method:'OPTIONS',headers:{Origin:'http://localhost:4173'}})).status,204);
    }
    const guarded=express();guarded.use(createPackageFeedbackAdminRouter({service}));const s=guarded.listen(0,'127.0.0.1');await once(s,'listening');try {assert.equal((await fetch(`http://127.0.0.1:${s.address().port}/`)).status,401);} finally {s.closeAllConnections();await new Promise(r=>s.close(r));}
  });
  await t.test('existing signed-cookie login protects package admin without a bypass',async()=>{
    const response=await fetch(base+'/admin/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'secret=package-admin-test',redirect:'manual'});assert.equal(response.status,303);
    const value=response.headers.get('set-cookie');for(const flag of ['HttpOnly','Secure','SameSite=Strict','Path=/admin']) assert.ok(value.includes(flag));cookie=value.split(';')[0];
    for(const route of ['/admin/package-feedback','/admin/assets/package-feedback.js','/admin/assets/package-feedback.css']) assert.equal((await fetch(base+route,{headers:{Cookie:cookie}})).status,200);
    const html=await (await fetch(base+'/admin/package-feedback',{headers:{Cookie:cookie}})).text();assert.match(html,/Package demo feedback/);assert.match(html,/Flight → package funnel/);
    const flightHtml=await (await fetch(base+'/admin/demo-feedback',{headers:{Cookie:cookie}})).text();assert.ok(flightHtml.includes('/admin/package-feedback'));
    for(const token of ['tampered',createAdminSessionToken('package-session-test',Date.now()-9*3600000)]) assert.equal((await fetch(base+'/admin/api/package-feedback',{headers:{Cookie:`${ADMIN_COOKIE}=${token}`}})).status,401);
  });
  const report=async query=>{const response=await fetch(base+'/admin/api/package-feedback'+query,{headers:{Cookie:cookie}});assert.equal(response.status,200);return response.json();};
  await t.test('package reports, filters and funnel use correct denominators without mixing flight results',async()=>{
    const all=await report('');assert.equal(all.demoType,'package');assert.equal(all.overall.total,2);assert.equal(all.overall.positive.percent,100);assert.equal(all.overall.usefulness.Yes.percent,50);assert.equal(all.overall.entryPaths.flight_thank_you.count,1);assert.deepEqual(all.funnel,packageFunnel(1,1,1));
    for(const [query,count] of [['?source=reddit',1],['?entry_path=direct',1],['?usefulness=No',0],['?likelihood=Probably',1],['?from=2000-01-01&to=2000-01-01',0]]) assert.equal((await report(query)).overall.total,count);
    assert.deepEqual((await report('?usefulness=No&likelihood=Probably&entry_path=direct')).funnel,all.funnel,'Answer filters must not change funnel denominators');
    assert.deepEqual((await report('?source=direct')).funnel,packageFunnel(0,0,0));assert.deepEqual((await report('?from=2000-01-01&to=2000-01-01')).funnel,packageFunnel(0,0,0));
    assert.equal((await report('?sort=oldest')).rows[0].entry_path,'flight_thank_you');assert.equal((await report('?sort=newest')).rows[0].entry_path,'direct');
    assert.equal((await fetch(base+'/admin/api/package-feedback?entry_path=invalid',{headers:{Cookie:cookie}})).status,400);
    assert.deepEqual(await flight.report({}),flightBefore);assert.deepEqual((await pool.query('select * from demo_feedback_responses')).rows,flightRows);
  });
  await t.test('separate HMAC rate limits deduplicate repeated clicks, expire and leave flight buckets alone',async()=>{
    const oldBuckets=(await pool.query('select * from demo_feedback_rate_limits')).rows;clock+=16*60*1000;
    const event=click({source:'rate-test'});
    for(let i=0;i<10;i++) assert.equal((await post(event,'/v1/package-feedback/events')).status,201);
    assert.equal((await post(event,'/v1/package-feedback/events')).status,429);
    for(let i=0;i<10;i++) assert.equal((await post(answer({source:'rate-test'}))).status,201);
    assert.equal((await post(answer())).status,429);
    let buckets=(await pool.query('select * from package_feedback_rate_limits')).rows;assert.equal(buckets.length,2);for(const row of buckets) assert.match(row.bucket_key,/^[a-f0-9]{64}$/);
    assert.equal((await pool.query("select count(*) from package_feedback_clicks where source='rate-test'")).rows[0].count,'1');
    clock+=16*60*1000;assert.equal((await post(answer({source:'rate-test'}))).status,201);buckets=(await pool.query('select * from package_feedback_rate_limits')).rows;assert.equal(buckets.length,1);
    assert.deepEqual((await pool.query('select * from demo_feedback_rate_limits')).rows,oldBuckets);
  });
  await t.test('filtered package CSV spans all pages and safely quotes comments',async()=>{
    for(let i=0;i<53;i++) await pool.query('insert into package_feedback_responses(id,request_id,likelihood,usefulness,comment,source,entry_path) values($1,$2,$3,$4,$5,$6,$7)',[crypto.randomUUID(),crypto.randomUUID(),'Probably not','No',i===0?'=HYPERLINK("bad")':`Sample ${i}`,'family','direct']);
    const all=await report('?source=family');assert.equal(all.overall.total,53);assert.equal(all.rows.length,50);assert.equal(all.pages,2);assert.equal((await report('?source=family&page=2')).rows.length,3);
    const response=await fetch(base+'/admin/api/package-feedback/export.csv?source=family&likelihood=Probably%20not&usefulness=No&entry_path=direct&page=1',{headers:{Cookie:cookie}});assert.equal(response.status,200);assert.match(response.headers.get('content-disposition'),/zippi-package-feedback-/);assert.match(response.headers.get('content-type'),/text\/csv/);const csv=await response.text();assert.equal(csv.trim().split('\r\n').length,54);for(const field of CSV_HEADERS) assert.ok(csv.includes(field));assert.ok(csv.includes('"\'=HYPERLINK'));assert.ok(!csv.includes('"reddit"'));
    const multiline=await (await fetch(base+'/admin/api/package-feedback/export.csv?source=reddit',{headers:{Cookie:cookie}})).text();assert.ok(multiline.includes('Flights, ""hotel""\ntogether.'));
    assert.equal((await fetch(base+'/admin/api/package-feedback/export.csv?source=bad@email',{headers:{Cookie:cookie}})).status,400);
    assert.deepEqual(await flight.report({}),flightBefore);
  });
  await t.test('database enforces package boundaries and grants PUBLIC no privileges',async()=>{
    for(const table of ['package_feedback_responses','package_feedback_clicks','package_feedback_rate_limits']) for(const privilege of ['SELECT','INSERT','UPDATE','DELETE']) assert.equal((await pool.query('select has_table_privilege($1,$2,$3) as allowed',['public',`${schema}.${table}`,privilege])).rows[0].allowed,false);
    await assert.rejects(pool.query("update package_feedback_responses set entry_path='bad'"),e=>e.code==='23514');
    await assert.rejects(pool.query("update package_feedback_responses set demo_type='flight'"),e=>e.code==='23514');
    await assert.rejects(pool.query("update package_feedback_responses set usefulness='Maybe'"),e=>e.code==='23514');
    assert.deepEqual((await pool.query('select * from demo_feedback_responses')).rows,flightRows);
  });
});
