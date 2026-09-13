const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { createDemoFeedbackService, validateSubmission, parseFilters, filterSql, summarize, csvCell, csvLine, COMPREHENSION_CHOICES } = require('../lib/demoFeedback');
const { createDemoFeedbackPublicRouter, createDemoFeedbackAdminRouter } = require('../lib/demoFeedbackRoutes');
const { createAdminDashboardRouter, createAdminSessionToken, ADMIN_COOKIE } = require('../lib/adminDashboard');

const answer = (extra={}) => ({ request_id:crypto.randomUUID(), comprehension_choice:'natural_language_flight_search', own_words:'It lets me describe the flight I want.', likelihood:'Definitely', additional_comments:'Less typing.', recent_flight_shopper:true, source:'reddit', ...extra });
test('feedback validates exact choices, required answers, text limits and source', () => {
  assert.equal(validateSubmission(answer()).source,'reddit');
  assert.equal(validateSubmission(answer({source:undefined})).source,'direct');
  assert.equal(validateSubmission(answer({additional_comments:undefined})).additional_comments,'');
  assert.equal(validateSubmission(answer({own_words:'  A flight finder.  '})).own_words,'A flight finder.');
  for(const change of [{comprehension_choice:undefined},{comprehension_choice:null},{comprehension_choice:''},{comprehension_choice:'anything'},{comprehension_choice:['natural_language_flight_search']},{own_words:'a'.repeat(2001)},{own_words:'a\0b'},{own_words:12},{additional_comments:12},{additional_comments:'x'.repeat(2001)},{likelihood:'Maybe'},{likelihood:['Definitely']},{recent_flight_shopper:'yes'},{source:'person@example.com'},{source:'http://url.test'},{source:'x'.repeat(65)},{website:'spam'},{request_id:'bad'}]) assert.throws(()=>validateSubmission(answer(change)),error=>error.status===400);
  assert.throws(()=>validateSubmission([]));
});
test('all five comprehension choices are accepted and both text fields are optional', () => {
  for(const choice of COMPREHENSION_CHOICES) assert.equal(validateSubmission(answer({comprehension_choice:choice.value})).comprehension_choice,choice.value);
  for(const value of [undefined,null,'','   ']) {
    const result=validateSubmission(answer({own_words:value,additional_comments:value}));assert.equal(result.own_words,'');assert.equal(result.additional_comments,'');
  }
});
test('comprehension percentages exclude earlier responses and keep neutral choices', () => {
  const groups=COMPREHENSION_CHOICES.map(choice=>({source:'reddit',likelihood:'Probably',recent_flight_shopper:true,comprehension_choice:choice.value,count:choice.value==='natural_language_flight_search'?3:1}));
  groups.push({source:'family',likelihood:'Probably',recent_flight_shopper:false,comprehension_choice:null,count:8});
  const data=summarize(groups);assert.equal(data.overall.total,15);assert.equal(data.overall.comprehension.answered,7);assert.equal(data.overall.comprehension.notAsked,8);assert.equal(data.overall.comprehension.correct.count,3);assert.equal(data.overall.comprehension.correct.percent,42.9);
  for(const choice of COMPREHENSION_CHOICES.slice(1)) assert.deepEqual([data.overall.comprehension.choices[choice.value].count,data.overall.comprehension.choices[choice.value].percent],[1,14.3]);
  assert.equal(data.shoppers.comprehension.correct.percent,42.9);assert.equal(data.sources.find(x=>x.source==='family').comprehension.correct.percent,null);assert.equal(summarize([]).overall.comprehension.correct.percent,null);
});
test('structured CSV includes choices, optional text and earlier question format', () => {
  const csv=csvLine({id:'example',comprehension_choice:'natural_language_flight_search',own_words:'Flights, "refined"\nby talking.',likelihood:'Probably',recent_flight_shopper:true,additional_comments:'=SUM(1,2)',source:'reddit',submitted_at:new Date('2026-09-13T12:00:00Z')});
  assert.ok(csv.includes('"natural_language_flight_search"'));assert.ok(csv.includes('"Flights, ""refined""\nby talking."'));assert.ok(csv.includes('multiple_choice_v2'));
  const earlier=csvLine({id:'earlier',own_words:'Original text',additional_comments:'Original reason',recent_flight_shopper:false});assert.ok(earlier.includes('"","Not asked (earlier form)","Original text"'));assert.ok(earlier.includes('"Original reason"'));assert.ok(earlier.includes('free_text_v1'));
});
test('filter validation and bound SQL cover date ranges and injection', () => {
  const filters=parseFilters({source:'reddit',likelihood:'Probably',recent:'yes',from:'2026-09-01',to:'2026-09-13',sort:'oldest',page:'2'});
  const sql=filterSql(filters); assert.equal(filters.page,2); assert.ok(sql.where.includes('source = $1'));
  assert.deepEqual(sql.params,['reddit','Probably',true,'2026-09-01T00:00:00Z','2026-09-14T00:00:00.000Z']);
  for(const query of [{source:"' or 1=1--"},{sort:'desc;drop table'},{recent:'maybe'},{from:'2026-02-30'},{from:'2026-09-14',to:'2026-09-13'},{page:'0'},{page:'10000000'},{source:['reddit','family']}]) assert.throws(()=>parseFilters(query),error=>error.status===400);
});
test('summary percentages have explicit denominators and empty states', () => {
  const data=summarize([{source:'reddit',likelihood:'Definitely',recent_flight_shopper:true,count:2},{source:'reddit',likelihood:'Probably',recent_flight_shopper:true,count:1},{source:'family',likelihood:'Probably not',recent_flight_shopper:false,count:1},{source:'direct',likelihood:'Definitely not',recent_flight_shopper:true,count:1}]);
  assert.equal(data.overall.total,5);assert.equal(data.overall.positive.percent,60);assert.equal(data.overall.recent.percent,80);assert.equal(data.shoppers.positive.percent,75);assert.equal(data.shoppers.likelihoods.Definitely.percent,50);assert.equal(data.sources[0].positive.percent,100);
  assert.equal(summarize([]).overall.positive.percent,0);
});
test('CSV escaping protects commas, quotes, line breaks and formula prefixes', () => {
  assert.equal(csvCell('a,"b"\nc'),'"a,""b""\nc"');
  for(const value of ['=SUM(1,2)','+cmd','-1+2','@SUM(A1)','  =1','\t=1','\r=1','\n@x']) assert.ok(csvCell(value).startsWith('"\''));
  assert.equal(csvCell('Toronto → Miami'),'"Toronto → Miami"');
});

const databaseUrl=process.env.DEMO_FEEDBACK_TEST_DATABASE_URL;
test('real PostgreSQL + HTTP + existing admin authentication', {skip:!databaseUrl}, async t => {
  const url=new URL(databaseUrl);
  assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname),'Integration tests require isolated loopback PostgreSQL');
  const {Pool}=require('pg'); const express=require('express');
  const schema=`feedback_test_${crypto.randomBytes(8).toString('hex')}`;
  const root=new Pool({connectionString:databaseUrl,ssl:false});await root.query(`create schema ${schema}`);
  const pool=new Pool({connectionString:databaseUrl,ssl:false,options:`-c search_path=${schema}`});
  await pool.query(fs.readFileSync(path.join(__dirname,'../migrations/016_demo_feedback.sql'),'utf8'));
  const legacyId=crypto.randomUUID();
  await pool.query("insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper,source) values($1,$2,'Original words','Probably','Original reason',true,'direct')",[legacyId,crypto.randomUUID()]);
  const legacyBefore=(await pool.query('select * from demo_feedback_responses where id=$1',[legacyId])).rows[0];
  await pool.query(fs.readFileSync(path.join(__dirname,'../migrations/017_demo_feedback_comprehension.sql'),'utf8'));
  const legacyAfter=(await pool.query('select * from demo_feedback_responses where id=$1',[legacyId])).rows[0];
  await assert.rejects(pool.query('update demo_feedback_responses set comprehension_choice=$1 where id=$2',['invalid_choice',legacyId]),error=>error.code==='23514');
  assert.equal(legacyAfter.comprehension_choice,null);delete legacyAfter.comprehension_choice;assert.deepEqual(legacyAfter,legacyBefore,'Migration must preserve all original values and timestamps');
  await pool.query('delete from demo_feedback_responses where id=$1',[legacyId]);
  let clock=Date.now();const service=createDemoFeedbackService({dbPool:pool,secret:'isolated-test-secret',now:()=>clock});
  const app=express();app.use(express.json({limit:'8kb'}));app.use(express.urlencoded({extended:false}));
  app.use('/v1/demo-feedback',createDemoFeedbackPublicRouter({service,allowedOrigins:'http://localhost:4173'}));
  app.use('/admin',createAdminDashboardRouter({dbPool:pool,adminSecret:'test-admin-key',sessionSecret:'test-session-key',demoFeedbackService:service}));
  const server=app.listen(0,'127.0.0.1');await once(server,'listening');const base=`http://127.0.0.1:${server.address().port}`;
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await pool.end();await root.query(`drop schema ${schema} cascade`);await root.end();});
  const post=body=>fetch(base+'/v1/demo-feedback',{method:'POST',headers:{'Content-Type':'application/json',Origin:'http://localhost:4173'},body:JSON.stringify(body)});
  let cookie;
  await t.test('anonymous submit stores answers; retry is idempotent and default source is direct',async()=>{
    const body=answer({own_words:'Flights, "refined"\nby talking.',additional_comments:'=HYPERLINK("bad")'});
    const result=await post(body);assert.equal(result.status,201);assert.equal(result.headers.get('access-control-allow-origin'),'http://localhost:4173');assert.equal(result.headers.get('cache-control'),'no-store');assert.deepEqual(await result.json(),{ok:true});
    assert.equal((await post(body)).status,201);
    assert.equal((await post({...body,likelihood:'Probably'})).status,409);
    assert.equal((await post(answer({source:undefined,likelihood:'Probably',recent_flight_shopper:false,comprehension_choice:'not_sure',own_words:undefined,additional_comments:undefined}))).status,201);
    const rows=(await pool.query('select * from demo_feedback_responses')).rows;assert.equal(rows.length,2);assert.equal(rows[1].source,'direct');assert.ok(rows[0].id);assert.ok(rows[0].submitted_at);assert.equal(rows[0].comprehension_choice,'natural_language_flight_search');assert.equal(rows[1].understanding,'');assert.equal(rows[1].reason,'');assert.equal(Object.hasOwn(rows[0],'ip'),false);
  });
  await t.test('invalid multiple-choice values and payloads are not inserted',async()=>{
    clock+=16*60*1000;
    for(const body of [answer({likelihood:'Maybe'}),answer({recent_flight_shopper:'true'}),answer({comprehension_choice:undefined}),answer({comprehension_choice:'invalid'}),answer({comprehension_choice:['not_sure']}),answer({website:'bot'})]) assert.equal((await post(body)).status,400);
    assert.equal((await pool.query('select count(*) from demo_feedback_responses')).rows[0].count,'2');
    assert.equal((await fetch(base+'/v1/demo-feedback',{method:'POST',headers:{'Content-Type':'text/plain'},body:'bad'})).status,415);
    assert.equal((await post(answer({own_words:'x'.repeat(9000)}))).status,413);
  });
  await t.test('public callers cannot read data, aggregates, exports, dashboard or admin assets',async()=>{
    for(const route of ['/v1/demo-feedback','/v1/demo-feedback/export.csv','/v1/demo-feedback/summary']) assert.equal((await fetch(base+route)).status,405);
    for(const route of ['/admin/api/demo-feedback','/admin/api/demo-feedback/export.csv']) {
      const response=await fetch(base+route);assert.equal(response.status,401);assert.equal(response.headers.get('cache-control'),'no-store');
    }
    for(const route of ['/admin/demo-feedback','/admin/assets/demo-feedback.js']) {
      const response=await fetch(base+route,{redirect:'manual'});assert.equal(response.status,302);assert.equal(response.headers.get('location'),'/admin/login');
    }
    const denied=await fetch(base+'/v1/demo-feedback',{method:'POST',headers:{Origin:'https://evil.test','Content-Type':'application/json'},body:JSON.stringify(answer())});assert.equal(denied.status,403);
    const preflight=await fetch(base+'/v1/demo-feedback',{method:'OPTIONS',headers:{Origin:'http://localhost:4173'}});assert.equal(preflight.status,204);
  });
  await t.test('existing login grants protected dashboard and signed-cookie API access',async()=>{
    const login=await fetch(base+'/admin/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'secret=test-admin-key',redirect:'manual'});assert.equal(login.status,303);
    const setCookie=login.headers.get('set-cookie');for(const flag of ['HttpOnly','Secure','SameSite=Strict','Path=/admin']) assert.ok(setCookie.includes(flag));cookie=setCookie.split(';')[0];
    const html=await fetch(base+'/admin/demo-feedback',{headers:{Cookie:cookie}});assert.equal(html.status,200);assert.ok((await html.text()).includes('Recent flight shoppers'));
    for(const token of ['tampered',createAdminSessionToken('test-session-key',Date.now()-9*3600000)]) assert.equal((await fetch(base+'/admin/api/demo-feedback',{headers:{Cookie:`${ADMIN_COOKIE}=${token}`}})).status,401);
    const standalone=express();standalone.use(createDemoFeedbackAdminRouter({service}));const s=standalone.listen(0,'127.0.0.1');await once(s,'listening');assert.equal((await fetch(`http://127.0.0.1:${s.address().port}/`)).status,401);s.closeAllConnections();await new Promise(r=>s.close(r));
  });
  const report=async query=>(await fetch(base+'/admin/api/demo-feedback'+query,{headers:{Cookie:cookie}})).json();
  await t.test('SQL filters, sorting, all source options and recent-shopper summary are correct',async()=>{
    const all=await report('');assert.equal(all.overall.total,2);assert.equal(all.overall.positive.percent,100);assert.equal(all.overall.recent.percent,50);assert.equal(all.shoppers.likelihoods.Definitely.percent,100);assert.equal(all.overall.comprehension.correct.percent,50);assert.equal(all.overall.comprehension.choices.not_sure.percent,50);assert.equal(all.shoppers.comprehension.correct.percent,100);
    for(const [query,count] of [['?source=reddit',1],['?recent=yes',1],['?likelihood=Probably',1],['?source=none',0],['?from=2000-01-01&to=2000-01-01',0]]) assert.equal((await report(query)).overall.total,count);
    const filtered=await report('?source=reddit&recent=yes');assert.deepEqual(filtered.sourceOptions,['direct','reddit']);assert.equal(filtered.rows[0].source,'reddit');assert.equal(filtered.overall.comprehension.correct.percent,100);assert.equal(filtered.rows[0].own_words,'Flights, "refined"\nby talking.');
    assert.equal((await report('?sort=oldest')).rows[0].likelihood,'Definitely');assert.equal((await report('?sort=newest')).rows[0].likelihood,'Probably');
    assert.equal((await fetch(base+'/admin/api/demo-feedback?from=not-a-date',{headers:{Cookie:cookie}})).status,400);
  });
  await t.test('rate limit is database-backed, stores only hashes and permits a later window',async()=>{
    clock+=16*60*1000;
    for(let i=0;i<10;i++) assert.equal((await post(answer())).status,201);
    assert.equal((await post(answer())).status,429);
    const buckets=(await pool.query('select * from demo_feedback_rate_limits')).rows;assert.equal(buckets.length,1);assert.match(buckets[0].bucket_key,/^[a-f0-9]{64}$/);
    clock+=16*60*1000;assert.equal((await post(answer({source:'altalab'}))).status,201);assert.equal((await pool.query('select count(*) from demo_feedback_rate_limits')).rows[0].count,'1');
  });
  await t.test('CSV exports all filtered rows across pages and escapes formulas and quoted newlines',async()=>{
    for(let i=0;i<53;i++) await pool.query('insert into demo_feedback_responses(id,request_id,understanding,likelihood,recent_flight_shopper,source) values($1,$2,$3,$4,$5,$6)',[crypto.randomUUID(),crypto.randomUUID(),`Sample ${i}`,'Probably not',false,'family']);
    const page=await report('?source=family');assert.equal(page.rows.length,50);assert.equal(page.overall.total,53);assert.equal(page.overall.comprehension.notAsked,53);assert.equal(page.overall.comprehension.correct.percent,null);assert.equal(page.pages,2);assert.equal((await report('?source=family&page=2')).rows.length,3);
    const response=await fetch(base+'/admin/api/demo-feedback/export.csv?source=family&page=1',{headers:{Cookie:cookie}});assert.equal(response.status,200);assert.match(response.headers.get('content-disposition'),/zippi-demo-feedback-\d{4}-\d{2}-\d{2}\.csv/);const exportText=await response.text();assert.equal(exportText.trim().split('\r\n').length,54);for(const header of ['Comprehension choice','Own-words description','Likelihood to use','Recent flight shopper','Additional comments','Source','Submitted at (UTC)']) assert.ok(exportText.includes(header));assert.ok(exportText.includes('free_text_v1'));
    const csv=await (await fetch(base+'/admin/api/demo-feedback/export.csv?source=reddit',{headers:{Cookie:cookie}})).text();assert.ok(csv.includes('Flights, ""refined""\nby talking.'));assert.ok(csv.includes("\"'=HYPERLINK"));
    const permissions=await pool.query("select has_table_privilege('public','demo_feedback_responses','select') as allowed");assert.equal(permissions.rows[0].allowed,false);
  });
});
