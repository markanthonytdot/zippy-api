const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const path=require('node:path');
const {discoverMigrations,runMigrations,migrationChecksum}=require('../lib/migrations');
const production=require('./fixtures/package-feedback-production-migrations.json');
const migrations=discoverMigrations(path.join(__dirname,'../migrations'));
test('018 follows the freshly verified immutable production history 001–017',()=>{
  assert.deepEqual(migrations.slice(0,17).map(({filename,checksum})=>({filename,checksum})),production.migrations);
  assert.deepEqual(migrations.map(m=>m.version),Array.from({length:18},(_,i)=>i+1));assert.equal(migrations[17].filename,'018_package_demo_feedback.sql');
});
const databaseUrl=process.env.PACKAGE_FEEDBACK_TEST_DATABASE_URL;
test('package migration safely upgrades history, preserves flight rows and rolls back on failure',{skip:!databaseUrl},async t=>{
  const url=new URL(databaseUrl);assert.ok(['localhost','127.0.0.1','[::1]'].includes(url.hostname));
  const {Client}=require('pg');const root=new Client({connectionString:databaseUrl,ssl:false});await root.connect();t.after(()=>root.end());
  async function isolated(body) {
    const name=`package_migrations_${crypto.randomBytes(6).toString('hex')}`;await root.query(`create database ${name}`);
    const child=new URL(url);child.pathname=`/${name}`;const client=new Client({connectionString:child.toString(),ssl:false});
    try {await client.connect();await body(client);} finally {await client.end();await root.query(`drop database ${name}`);}
  }
  const run=(client,selected=migrations)=>runMigrations({client,migrations:selected,log:()=>{}});
  const ledger=async client=>(await client.query('select * from schema_migrations order by filename')).rows;
  const snapshot=async client=>({rows:(await client.query('select * from demo_feedback_responses order by id')).rows,columns:(await client.query("select * from information_schema.columns where table_schema='public' and table_name like 'demo_feedback%' order by table_name,ordinal_position")).rows,constraints:(await client.query("select conname,pg_get_constraintdef(oid) as def from pg_constraint where conrelid='demo_feedback_responses'::regclass order by conname")).rows});
  await t.test('fresh install and deterministic second run',()=>isolated(async client=>{
    await run(client);assert.equal((await ledger(client)).length,18);const before=await ledger(client);await run(client);assert.deepEqual(await ledger(client),before);
    for(const table of ['package_feedback_responses','package_feedback_clicks','package_feedback_rate_limits']) assert.equal((await client.query(`select count(*) from ${table}`)).rows[0].count,'0');
  }));
  for(const fail of [false,true]) await t.test(fail?'failed 018 rolls back all new tables and can safely resume':'upgrade retains all 17 ledger entries and original flight rows',()=>isolated(async client=>{
    await run(client,migrations.slice(0,17));
    await client.query("insert into demo_feedback_responses(id,request_id,understanding,likelihood,reason,recent_flight_shopper,source,comprehension_choice) values($1,$2,'Preserved synthetic words','Probably','Original comment',true,'test','natural_language_flight_search')",[crypto.randomUUID(),crypto.randomUUID()]);
    const prior=await ledger(client);const before=await snapshot(client);
    if(fail) {
      const sql=migrations[17].sql+'\nselect 1/0;';const broken=[...migrations.slice(0,17),{...migrations[17],sql,checksum:migrationChecksum(Buffer.from(sql))}];
      await assert.rejects(run(client,broken),e=>e.code==='22012');assert.deepEqual(await ledger(client),prior);assert.deepEqual(await snapshot(client),before);
      for(const table of ['package_feedback_responses','package_feedback_clicks','package_feedback_rate_limits']) assert.equal((await client.query('select to_regclass($1) as found',[table])).rows[0].found,null);
    }
    await run(client);assert.deepEqual((await ledger(client)).slice(0,17),prior);assert.deepEqual(await snapshot(client),before);assert.equal((await ledger(client)).length,18);
    assert.equal((await client.query('select count(*) from package_feedback_responses')).rows[0].count,'0');
  }));
});
