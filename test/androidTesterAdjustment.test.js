const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture } = require('../test-support/androidTesterFixture');
const { input } = require('../lib/androidTesterRoutes');
const day = 86400000;
const request = (row, operation, durationDays) => ({ id: row.id, operation, durationDays, expectedExpiresAt: row.expiresAt, confirm: true });
for (const [initial, operation, days] of [[7,'set',1],[1,'set',30],[30,'set',5],[7,'extend',5],[1,'set',90]]) {
  test(`Android ${initial} days → ${operation} ${days}: exact UTC, state preservation and audit`, async t => {
    const f=await fixture(t);let row=(await f.run('prepare',{email:'adjust@example.test',durationDays:initial})).invitation;
    row=(await f.run('confirm',{id:row.id,confirm:true})).invitation;
    f.advance(3600000);const timestamp=f.state.now;
    const before=(await f.pool.query('select * from partner_people')).rows[0];
    const next=(await f.run('adjust',request(row,operation,days))).invitation;
    assert.equal(Date.parse(next.expiresAt),(operation==='set'?timestamp:Date.parse(row.expiresAt))+days*day);
    assert.equal(next.access,'active');assert.equal(next.playEligibility,'confirmed');assert.equal(next.emailStatus,'not_sent');
    const after=(await f.pool.query('select * from partner_people')).rows[0];
    for(const key of ['starts_at','status','revoked_at','features','platforms','organization_id']) assert.deepEqual(after[key],before[key],key);
    const audit=(await f.pool.query("select metadata,created_at from partner_access_audit where event='access_adjusted'")).rows;
    assert.equal(audit.length,1);assert.equal(+audit[0].created_at,timestamp);
    assert.deepEqual(audit[0].metadata,{operation,durationDays:days,previousExpiresAt:row.expiresAt,expiresAt:next.expiresAt,adjustedAt:new Date(timestamp).toISOString()});
    await assert.rejects(f.run('adjust',request(row,operation,days)),{code:'expiry_changed'});
    assert.equal(f.state.emails.length+f.state.challenges.length,0);
  });
}
for (const operation of ['set','extend']) test(`Android ${operation}: expired access eligible; revoked and disabled remain blocked`,async t=>{
  const f=await fixture(t);let row=await f.prepare();f.state.now=Date.parse(row.expiresAt)+1000;
  assert.equal((await f.service.list()).invitations[0].access,'expired');
  row=(await f.run('adjust',request(row,operation,2))).invitation;
  assert.equal(Date.parse(row.expiresAt),f.state.now+2*day);assert.equal(row.access,'active');
  for(const action of ['revoke','disable']) {
    row=(await f.run(action,{id:row.id})).invitation;
    row=(await f.run('adjust',request(row,operation,5))).invitation;
    assert.equal(row.access,action==='disable'?'disabled':'revoked');
    await f.access.requestCode({email:row.email,platform:'android',ip:'192.0.2.34'});
  }
  assert.equal(f.state.emails.length+f.state.challenges.length,0);
});
test('Android adjustment independently rejects invalid durations, ambiguous operations, missing confirmation and stale writes',async t=>{
  const f=await fixture(t);const row=await f.prepare();const person=(await f.pool.query('select id from partner_people')).rows[0];
  const base=request(row,'set',1);
  for(const durationDays of [0,91,-1,1.5,'','abc','2',null,undefined,true,{}]) {
    await assert.rejects(f.run('adjust',{...base,durationDays}),{code:'invalid_duration'});
    await assert.rejects(f.access.changePerson(person.id,'adjust',{...base,durationDays},'qa'),{code:'invalid_duration'});
  }
  for(const operation of ['',null,undefined,'restore','expiry']) await assert.rejects(f.run('adjust',{...base,operation}),{code:'invalid_adjustment'});
  for(const fields of [{confirm:false},{confirm:undefined},{expectedExpiresAt:undefined}]) {
    await assert.rejects(f.run('adjust',{...base,...fields}),{code:'manual_confirmation_required'});
    await assert.rejects(f.access.changePerson(person.id,'adjust',{...base,...fields},'qa'),{code:'manual_confirmation_required'});
  }
  await assert.rejects(f.access.changePerson(person.id,'adjust',{...base,expiresAt:'2099-01-01T00:00:00Z'},'qa'),{code:'invalid_duration'});
  const results=await Promise.allSettled([5,10].map(durationDays=>f.access.changePerson(person.id,'adjust',{...base,durationDays},'qa')));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(results.find(r=>r.status==='rejected').reason.code,'expiry_changed');
  assert.equal((await f.pool.query("select count(*) from partner_access_audit where event='access_adjusted'")).rows[0].count,'1');
});
test('adjusted Android expiry survives Prepare, eligibility, mocked resend/OTP and session checks, then expires',async t=>{
  const f=await fixture(t);let row=await f.prepare();row=(await f.run('adjust',request(row,'set',1))).invitation;const expiry=row.expiresAt;
  f.advance();assert.equal((await f.run('prepare',{email:row.email,durationDays:90})).invitation.expiresAt,expiry);
  for(const action of ['confirm','unconfirm','removed','confirm']) assert.equal((await f.run(action,{id:row.id,confirm:true})).invitation.expiresAt,expiry);
  await f.run('send',{id:row.id});f.advance();assert.equal((await f.run('resend',{id:row.id})).invitation.expiresAt,expiry);
  const req={email:row.email,platform:'android',ip:'192.0.2.24'};
  await f.access.requestCode(req);f.advance(61000);await f.access.requestCode(req);
  const verified=await f.access.verifyCode({...req,code:f.state.challenges.at(-1).code});const claims=await f.claims(verified.token);
  assert.equal(verified.partnerAccess.expiresAt,expiry);f.advance();assert.equal((await f.access.status(claims)).expiresAt,expiry);
  f.state.now=Date.parse(expiry);assert.equal((await f.access.status(claims)).access,'expired');
  const count=f.state.challenges.length;await f.access.requestCode(req);assert.equal(f.state.challenges.length,count);
  await assert.rejects(f.run('prepare',{email:row.email,durationDays:90}),{code:'preview_access_inactive'});
  assert.equal((await f.service.list()).invitations[0].expiresAt,expiry);
});
test('adjustment wire fields cannot leak into Prepare/resend/eligibility or bypass authority',()=>{
  const body={action:'adjust',platform:'android',operation:'set',durationDays:5,confirm:true,expectedExpiresAt:'expiry',expiresAt:'forged',status:'active'};
  assert.deepEqual(input(body),{action:'adjust',platform:'android',id:undefined,email:undefined,confirm:true,operation:'set',durationDays:5,expectedExpiresAt:'expiry'});
  for(const action of ['prepare','send','resend','confirm','removed']) assert.equal(input({...body,action}).operation,undefined);
});
