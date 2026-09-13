// Uses synthetic rows in a disposable local schema and a separate loopback API.
const { sharedAdminFixture } = require('../test/helpers/sharedAdminFixture');
if (process.env.NODE_ENV === 'production' || process.env.AUTH_MODE === 'prod') throw new Error('Local preview only');
sharedAdminFixture({port:4320}).then(fixture=>{
  console.log('Local shared-admin preview: http://localhost:4320/admin/partner-access');
  console.log('Uses only synthetic local fixtures; no production connection.');
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,async()=>{await fixture.close();process.exit(0);});
}).catch(()=>{console.error('Local shared-admin preview could not start.');process.exitCode=1;});
