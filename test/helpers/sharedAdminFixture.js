// Isolated local acceptance only. No production URL, credential, provider or email.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { once } = require('node:events');
const { Pool } = require('pg');
const express = require('express');
const helmet = require('helmet');
const { createAdminDashboardRouter } = require('../../lib/adminDashboard');
const { createFeedbackAdminRemote } = require('../../lib/feedbackAdminRemote');
async function sharedAdminFixture({ port = 0 } = {}) {
  const api = process.env.FEEDBACK_API_TEST_ROOT;
  assert.ok(api && path.isAbsolute(api), 'FEEDBACK_API_TEST_ROOT must identify the reviewed local API candidate');
  const database = process.env.FEEDBACK_AUTH_TEST_DATABASE_URL;
  assert.ok(database && ['127.0.0.1','localhost','[::1]'].includes(new URL(database).hostname), 'Loopback test PostgreSQL required');
  const schema='shared_admin_'+crypto.randomBytes(8).toString('hex');
  const setup=new Pool({connectionString:database,ssl:false});await setup.query(`create schema ${schema}`);
  const pool=new Pool({connectionString:database,ssl:false,options:`-c search_path=${schema}`});
  for(const file of ['016_demo_feedback.sql','017_demo_feedback_comprehension.sql','018_package_demo_feedback.sql']) await pool.query(fs.readFileSync(path.join(api,'migrations',file),'utf8'));
  const flight=require(path.join(api,'lib/demoFeedback')).createDemoFeedbackService({dbPool:pool,secret:crypto.randomBytes(32).toString('hex')});
  const packages=require(path.join(api,'lib/packageFeedback')).createPackageFeedbackService({dbPool:pool,secret:crypto.randomBytes(32).toString('hex')});
  await flight.submit({request_id:crypto.randomUUID(),comprehension_choice:'natural_language_flight_search',likelihood:'Definitely',recent_flight_shopper:true,source:'test',own_words:'Flights in my own words.',additional_comments:'=LOCAL_FORMULA'},'local-fixture');
  await flight.submit({request_id:crypto.randomUUID(),comprehension_choice:'not_sure',likelihood:'Probably',recent_flight_shopper:false,source:'local-other'},'local-fixture');
  await packages.submit({request_id:crypto.randomUUID(),demo_type:'package',source:'test',entry_path:'direct',likelihood:'Definitely',usefulness:'Yes',comment:'=LOCAL_FORMULA'},'local-fixture');
  await packages.recordClick({event_id:crypto.randomUUID(),source:'test',entry_path:'flight_thank_you'},'local-fixture');
  const secret=crypto.randomBytes(32).toString('hex');
  const upstream=express();upstream.use('/internal/feedback-read',require(path.join(api,'lib/feedbackReadBridge')).createFeedbackReadBridgeRouter({secret,flight,packages}));
  const upstreamServer=upstream.listen(0,'127.0.0.1');await once(upstreamServer,'listening');
  const forwarded=[];
  const remote=createFeedbackAdminRemote({secret,endpoint:`http://127.0.0.1:${upstreamServer.address().port}/internal/feedback-read`,fetchImpl:async(url,options)=>{
    forwarded.push({url,headerNames:Object.keys(options.headers),method:options.method,redirect:options.redirect});return fetch(url,options);
  }});
  const adminPassword='local-preview-only'; const sessionSecret=crypto.randomBytes(32).toString('hex');
  const app=express();app.use(helmet());app.use(express.json());app.use(express.urlencoded({extended:false}));
  const testerWrites=[];
  app.use('/admin',createAdminDashboardRouter({adminSecret:adminPassword,sessionSecret,feedbackAdmin:remote,
    partnerAccessService:{list:async()=>({ok:true,organizations:[],people:[]}),createOrganization:async(body)=>{testerWrites.push('ios');return {ok:true,organization:body};}},
    testerInvitationService:{list:async()=>({ok:true,config:{enabled:true,policyConfigured:true,emailConfigured:false,platforms:{ios:true,android:false}},invitations:[],organizations:[]})},
    androidTesterService:{list:async()=>({ok:true,config:{enabled:true,authority:'production'},invitations:[]}),run:async()=>{testerWrites.push('android');return {ok:true};}},
  }));
  const server=app.listen(port,'127.0.0.1');await once(server,'listening');
  return {base:`http://localhost:${server.address().port}`,adminPassword,sessionSecret,forwarded,testerWrites,pool,secret,
    async close(){for(const s of [server,upstreamServer]){s.closeAllConnections();await new Promise(r=>s.close(r));}await pool.end();await setup.query(`drop schema ${schema} cascade`);await setup.end();}};
}
module.exports={sharedAdminFixture};
