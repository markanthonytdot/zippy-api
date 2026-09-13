// Local preview only: real PostgreSQL, existing admin auth, no provider/app/store calls.
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const { Pool } = require('pg');
const { createAdminDashboardRouter } = require('../lib/adminDashboard');
const { createDemoFeedbackService } = require('../lib/demoFeedback');
const { createDemoFeedbackPublicRouter } = require('../lib/demoFeedbackRoutes');
const { installPackageFeedbackRuntime } = require('../lib/packageFeedbackRoutes');

async function main() {
  if (process.env.NODE_ENV === 'production' || process.env.AUTH_MODE === 'prod') throw new Error('Local preview is disabled in production.');
  const url = new URL(process.env.DEMO_FEEDBACK_DEV_DATABASE_URL || 'postgres://marks@127.0.0.1:55438/postgres');
  if (!['postgres:','postgresql:'].includes(url.protocol) || !['localhost','127.0.0.1','[::1]'].includes(url.hostname)) throw new Error('An isolated loopback PostgreSQL database is required.');
  if (!process.env.DEMO_FEEDBACK_DEV_ADMIN_SECRET) throw new Error('Set a local-only DEMO_FEEDBACK_DEV_ADMIN_SECRET.');
  const dbPool = new Pool({ connectionString:url.toString(),ssl:false });
  await dbPool.query('select id from demo_feedback_responses limit 0');
  await dbPool.query('select id from package_feedback_responses limit 0');
  const port = Number(process.env.DEMO_FEEDBACK_DEV_PORT || 4318);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid local preview port.');
  const allowedOrigins = `http://localhost:${port},http://127.0.0.1:${port},http://localhost:4173,http://127.0.0.1:4173`;
  const secret=crypto.randomBytes(32).toString('hex');
  const service=createDemoFeedbackService({dbPool,secret});
  const app=express(); app.use(helmet({ contentSecurityPolicy:false })); app.use(express.json({limit:'8kb'})); app.use(express.urlencoded({extended:false}));
  app.use('/v1/demo-feedback',createDemoFeedbackPublicRouter({service,allowedOrigins}));
  const packageService = installPackageFeedbackRuntime(app,{dbPool,secret,environment:{ZIPPI_PACKAGE_FEEDBACK_ENABLED:'true',PACKAGE_FEEDBACK_CORS_ORIGINS:allowedOrigins}});
  app.get(['/admin','/admin/'],(_req,res)=>res.redirect('/admin/demo-feedback'));
  app.use('/admin',createAdminDashboardRouter({dbPool,adminSecret:process.env.DEMO_FEEDBACK_DEV_ADMIN_SECRET,sessionSecret:secret,demoFeedbackService:service,packageFeedbackService:packageService}));
  const website=path.resolve(process.env.DEMO_FEEDBACK_WEBSITE_ROOT || '/Volumes/PERSONAL/heyzippi-website');
  app.use(express.static(website,{dotfiles:'deny'}));
  const server=app.listen(port,'127.0.0.1',()=>console.log(`LOCAL ONLY: http://localhost:${port}/demo-feedback/, /package-feedback/ and /admin/package-feedback`));
  for(const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close(()=>dbPool.end().then(()=>process.exit(0))));
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
