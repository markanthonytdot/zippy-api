const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {Pool}=require('pg');
const express=require('express');
const {createPartnerAccessService}=require('../lib/partnerAccess');
const {createPartnerAdminRouter}=require('../lib/partnerAccessRoutes');
const day=86400000;
async function fixture(t) {
  const connectionString=process.env.PARTNER_TEST_DATABASE_URL;
  assert.ok(connectionString&&['localhost','127.0.0.1'].includes(new URL(connectionString).hostname));
  const schema='access_adjust_'+crypto.randomBytes(8).toString('hex');
  const setup=new Pool({connectionString});await setup.query(`create schema ${schema}`);
  const pool=new Pool({connectionString,options:`-c search_path=${schema}`});
  t.after(async()=>{await pool.end();await setup.query(`drop schema ${schema} cascade`);await setup.end()});
  await pool.query(fs.readFileSync(path.join(__dirname,'../migrations/013_partner_access.sql'),'utf8'));
  const state={now:Date.parse('2026-10-31T17:00:00Z'),mail:[]}; // Spans a DST change: days still mean 24 hours.
  const service=createPartnerAccessService({dbPool:pool,secret:'local-adjustment-fixture',now:()=>state.now,
    signToken:async()=> 'local-token-not-used',mailAdapter:{configured:true,async send(message){state.mail.push(message)}}});
  const org=(await service.createOrganization({name:'Local adjustment fixture',allowedEmailDomains:['example.test']},'qa')).organization;
  const create=async(platform,durationDays=7,extra={})=>(await service.createPerson({email:`${crypto.randomUUID()}@example.test`,organizationId:org.id,platforms:[platform],durationDays,...extra},'qa')).person;
  const adjust=(person,operation,durationDays,extra={})=>service.changePerson(person.id,'adjust',{operation,durationDays,confirm:true,expectedExpiresAt:person.expiresAt,...extra},'qa');
  return {pool,service,state,create,adjust};
}
for(const platform of ['ios','android']) test(`${platform} Set/Extend uses server UTC and blocked-state-safe audited mutations`,async t=>{
 const f=await fixture(t);let person=await f.create(platform);
 for(const [operation,days] of [['set',1],['set',30],['set',5],['extend',5]]) {
  const previous=person;const before=f.state.now;
  person=(await f.adjust(person,operation,days)).person;
  assert.equal(Date.parse(person.expiresAt),(operation==='set'?before:Math.max(before,Date.parse(previous.expiresAt)))+days*day);
  assert.equal(person.access,'active');assert.equal(person.startsAt,previous.startsAt);
  const audit=(await f.pool.query("select metadata from partner_access_audit where event='access_adjusted' and person_id=$1 order by id desc limit 1",[person.id])).rows[0].metadata;
  assert.equal(audit.operation,operation);assert.equal(audit.previousExpiresAt,previous.expiresAt);assert.equal(audit.expiresAt,person.expiresAt);assert.equal(audit.adjustedAt,new Date(before).toISOString());
  f.state.now+=1000;
 }
 const claims={sub:`partner:${person.id}`,auth_method:'partner_preview',partner_invite_id:person.id,platform};
 f.state.now=Date.parse(person.expiresAt);assert.equal((await f.service.status(claims)).access,'expired');
 person=(await f.adjust(person,'set',2)).person;assert.equal(person.access,'active');
 assert.equal(Date.parse(person.expiresAt),f.state.now+2*day);
 for(const action of ['revoke','update']) {
  person=(await f.service.changePerson(person.id,action,action==='update'?{status:'disabled'}:{},'qa')).person;
  for(const operation of ['set','extend']) {
   person=(await f.adjust(person,operation,1)).person;
   assert.equal(person.access,action==='update'?'disabled':'revoked');
   await f.service.requestCode({email:person.email,platform,ip:'192.0.2.7'});
  }
 }
 assert.equal(f.state.mail.length,0);
});
test('direct admin adjustment validates operation/duration/confirmation and preserves scheduled start',async t=>{
 const f=await fixture(t);const person=await f.create('ios');
 for(const days of [undefined,null,'',0,-1,91,1.5,'abc','5',true]) await assert.rejects(f.adjust(person,'set',days),{code:'invalid_duration'});
 for(const operation of [undefined,null,'restore','']) await assert.rejects(f.adjust(person,operation,1),{code:'invalid_adjustment'});
 await assert.rejects(f.adjust(person,'set',1,{confirm:false}),{code:'manual_confirmation_required'});
 await assert.rejects(f.adjust(person,'set',1,{expectedExpiresAt:undefined}),{code:'manual_confirmation_required'});
 await assert.rejects(f.adjust(person,'set',1,{expiresAt:'2099-01-01T00:00:00Z'}),{code:'invalid_duration'});
 const scheduled=await f.create('ios',7,{startsAt:new Date(f.state.now+2*day).toISOString()});
 await assert.rejects(f.adjust(scheduled,'set',1),{code:'invalid_expiry'});
 assert.equal((await f.pool.query("select count(*) from partner_access_audit where event='access_adjusted'")).rows[0].count,'0');
});
test('signed admin route carries Set/Extend, prevents stale writes and rejects cross-origin/anonymous access',async t=>{
 const f=await fixture(t);let person=await f.create('ios');
 const app=express();app.use(express.json());app.use((req,res,next)=>{if(req.get('x-local-fixture')==='admin') req.zippiAdmin={actor:'qa'};next()});
 app.use('/admin/api/partner-access',createPartnerAdminRouter({service:f.service}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s))});
 t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve)}));
 const base=`http://127.0.0.1:${server.address().port}`;
 const post=(body,headers={})=>fetch(`${base}/admin/api/partner-access/people/${person.id}/adjust`,{method:'POST',headers:{'content-type':'application/json',origin:base,'x-local-fixture':'admin',...headers},body:JSON.stringify(body)});
 for(const operation of ['set','extend']) {
  const body={operation,durationDays:1,confirm:true,expectedExpiresAt:person.expiresAt};
  assert.equal((await post(body,{'x-local-fixture':''})).status,401);assert.equal((await post(body,{origin:'https://untrusted.example'})).status,403);
  const reply=await post(body);assert.equal(reply.status,200);person=(await reply.json()).person;
  assert.equal((await post(body)).status,409);
 }
 assert.equal(f.state.mail.length,0);
});
