const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { once } = require('node:events');
const { QA_RESPONSE_IDS, INTERNAL_SOURCE, createPartnerFeedbackService, createPartnerFeedbackRouter } = require('../lib/partnerFeedback');

test('internal source markers exclude QA, test, local and internal submissions', () => {
  const re = new RegExp(INTERNAL_SOURCE, 'i');
  for (const source of ['qa','test','local-test','synthetic','internal','staff','dev','preview','smoke','e2e','automation','automated','qa-v4','v4_test','test123','qa2','local_test','QA']) assert.match(source,re,source);
  for (const source of ['direct','friends','linkedin','newsletter','travel-partners']) assert.doesNotMatch(source,re,source);
});

test('cache deduplicates reads, expires, and errors never expose DB details', async () => {
  let now=0, calls=0, released=0, fail=false;
  const sql=[];
  const service=createPartnerFeedbackService({now:()=>now,dbPool:{async connect(){calls++;return {async query(q){sql.push(q);if(fail && q.includes('select'))throw Error('PRIVATE_DATABASE_DETAIL');return {rows:[{understanding:'75.0',intent:'50.0'}]};},release(){released++;}};}}});
  const results=await Promise.all([service(),service(),service()]);
  assert.deepEqual(results[0],{understandingPercent:75,intentPercent:50});assert.equal(calls,1);assert.equal(released,1);
  assert.equal(sql[0],'begin read only');assert.equal(sql.at(-1),'commit');
  now=61000;await service();assert.equal(calls,2);
  now=122000;fail=true;await assert.rejects(service());assert.equal(sql.at(-1),'rollback');assert.equal(released,3);
  fail=false;await service();assert.equal(calls,4);
});

const databaseUrl=process.env.DEMO_FEEDBACK_TEST_DATABASE_URL;
test('PostgreSQL aggregate isolates v4, exact answer values, genuine sources and GET-only privacy', {skip:!databaseUrl}, async t=>{
  const url=new URL(databaseUrl);assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname));
  const {Client,Pool}=require('pg'),express=require('express');
  const root=new Client({connectionString:databaseUrl,ssl:false});await root.connect();
  const database='partner_feedback_'+crypto.randomBytes(6).toString('hex');await root.query(`create database ${database}`);url.pathname='/'+database;
  const pool=new Pool({connectionString:url.toString(),ssl:false});let server;
  t.after(async()=>{if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}await pool.end();await root.query(`drop database ${database}`);await root.end();});
  await pool.query(fs.readFileSync(require.resolve('../migrations/020_combined_demo_v4_feedback.sql'),'utf8'));
  // Same positive values in old tables must never contribute.
  for(const table of ['demo_feedback_responses','package_feedback_responses','package_feedback_clicks','combined_demo_feedback_responses'])await pool.query(`create table ${table}(id text,clarity text,use_likelihood text);insert into ${table} values('history','Very clear','Definitely')`);
  const add=async({id=crypto.randomUUID(),source='direct',clarity='Very clear',intent='Definitely',booked=true}={})=>pool.query('insert into combined_demo_v4_feedback_responses(id,request_id,survey_version,clarity,use_likelihood,booked_travel_last_12_months,source) values($1,$2,\'combined_demo_v4\',$3,$4,$5,$6)',[id,crypto.randomUUID(),clarity,intent,booked,source]);
  let clock=0;const read=createPartnerFeedbackService({dbPool:pool,now:()=>++clock*61000});
  assert.deepEqual(await read(),{understandingPercent:null,intentPercent:null});
  for(const id of QA_RESPONSE_IDS)await add({id,source:'direct'}); // ID exclusion survives misleading source.
  for(const source of ['test','qa-v4','local-test','synthetic','internal','staff','automation'])await add({source});
  assert.deepEqual(await read(),{understandingPercent:null,intentPercent:null});
  await add();assert.deepEqual(await read(),{understandingPercent:100,intentPercent:100});
  await add({clarity:'Somewhat clear',intent:'Probably',booked:false});
  await add({clarity:'Not very clear',intent:'Probably not'});
  await add({clarity:'Not clear at all',intent:'Definitely not'});
  assert.deepEqual(await read(),{understandingPercent:50,intentPercent:50});
  await add({clarity:'Somewhat clear',intent:'Probably',source:'friends',booked:false});
  await add({clarity:'Very clear',intent:'Definitely not',source:'linkedin'});
  assert.deepEqual(await read(),{understandingPercent:66.7,intentPercent:50});
  const tables=['combined_demo_v4_feedback_responses','combined_demo_v4_feedback_comments','demo_feedback_responses','package_feedback_responses','package_feedback_clicks','combined_demo_feedback_responses'];
  const snapshot=async()=>{const out={};for(const table of tables)out[table]=(await pool.query(`select to_jsonb(t)::text as row from ${table} t order by row`)).rows;return out;};
  const before=await snapshot();
  const app=express();app.use('/v1/partner-feedback',createPartnerFeedbackRouter({dbPool:pool}));
  app.use('/failure',createPartnerFeedbackRouter({dbPool:{async connect(){throw Error('PRIVATE_DATABASE_DETAIL');}}}));
  server=app.listen(0,'127.0.0.1');await once(server,'listening');const base=`http://127.0.0.1:${server.address().port}`;
  for(let i=0;i<3;i++){const response=await fetch(base+'/v1/partner-feedback',{headers:{Origin:'https://www.heyzippi.com'}});assert.equal(response.status,200);assert.equal(response.headers.get('access-control-allow-origin'),'https://www.heyzippi.com');const body=await response.json();assert.deepEqual(body,{understandingPercent:66.7,intentPercent:50});assert.deepEqual(Object.keys(body),['understandingPercent','intentPercent']);}
  for(const query of ['source=direct','id=history','survey_version=combined_demo_v3','page=1'])assert.equal((await fetch(base+'/v1/partner-feedback?'+query)).status,400);
  for(const method of ['POST','PUT','DELETE','PATCH'])assert.equal((await fetch(base+'/v1/partner-feedback',{method})).status,405);
  assert.equal((await fetch(base+'/v1/partner-feedback/export.csv')).status,405);
  assert.equal((await fetch(base+'/v1/partner-feedback',{method:'OPTIONS',headers:{Origin:'https://heyzippi.com','Access-Control-Request-Method':'GET'}})).status,204);
  assert.equal((await fetch(base+'/v1/partner-feedback',{method:'OPTIONS',headers:{Origin:'https://unrelated.example'}})).status,403);
  const failure=await fetch(base+'/failure');assert.equal(failure.status,503);assert.deepEqual(await failure.json(),{error:'feedback_unavailable'});
  assert.deepEqual(await snapshot(),before);
});
