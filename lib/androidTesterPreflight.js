const { validateMigrationLedger } = require('./migrations');
const TABLES = ['partner_organizations', 'partner_people', 'partner_verifications', 'partner_access_audit', 'partner_access_rate_limits', 'tester_invitations'];
async function preflightAndroidTesterSchema(client, migrations) {
  const ledger = (await client.query('select filename, checksum from schema_migrations order by filename')).rows;
  validateMigrationLedger(migrations, ledger); // Same immutable-ledger guard as deployment migrations.
  if (!ledger.some(row => row.filename === '012_flight_live_readiness.sql')) throw new Error('Production baseline migrations 001–012 must be present');
  const names = new Set(ledger.map(row => row.filename));
  const present = (await client.query(`select table_name from information_schema.tables
    where table_schema=current_schema() and table_name = any($1::text[])`, [TABLES])).rows.map(row => row.table_name);
  if (!names.has('013_partner_access.sql') && present.length) throw new Error('Untracked tester tables require review before migration');
  if (names.has('013_partner_access.sql') && TABLES.slice(0,5).some(table => !present.includes(table))) throw new Error('Partner schema does not match migration ledger');
  if (names.has('014_tester_invitations.sql') && !present.includes('tester_invitations')) throw new Error('Invitation schema does not match migration ledger');
  if (names.has('015_android_tester_eligibility.sql')) {
    const fields = (await client.query(`select column_name from information_schema.columns where table_schema=current_schema()
      and table_name='tester_invitations' and column_name in ('play_eligibility','play_eligibility_at','play_eligibility_actor')`)).rows;
    if (fields.length !== 3) throw new Error('Android eligibility schema does not match migration ledger');
  }
  return { ok: true, applied: ledger.length, pending: migrations.filter(m => !names.has(m.filename)).map(m => m.filename), testerTableCount: present.length };
}
module.exports = { preflightAndroidTesterSchema };
