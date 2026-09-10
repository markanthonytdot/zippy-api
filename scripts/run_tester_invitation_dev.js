// Local dashboard acceptance harness: isolated ephemeral schema, .test addresses, no external calls.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const { createPartnerAccessService } = require("../lib/partnerAccess");
const { createTesterInvitationService } = require("../lib/testerInvitations");
const { createAdminDashboardRouter } = require("../lib/adminDashboard");

async function main() {
  if (process.env.NODE_ENV === "production" || process.env.AUTH_MODE === "prod") throw new Error("Local harness only");
  const databaseUrl = process.env.PARTNER_TEST_DATABASE_URL;
  if (!databaseUrl || !["127.0.0.1", "localhost", "[::1]"].includes(new URL(databaseUrl).hostname)) throw new Error("Isolated loopback PostgreSQL required");
  if (!process.env.TESTER_DEV_ADMIN_SECRET) throw new Error("TESTER_DEV_ADMIN_SECRET is required");
  const schema = `tester_ui_${crypto.randomBytes(8).toString("hex")}`;
  const setup = new Pool({ connectionString: databaseUrl, ssl: false });
  await setup.query(`create schema ${schema}`);
  const pool = new Pool({ connectionString: databaseUrl, ssl: false, options: `-c search_path=${schema}` });
  for (const file of ["013_partner_access.sql", "014_tester_invitations.sql"]) await pool.query(fs.readFileSync(path.join(__dirname, "../migrations", file), "utf8"));
  const service = createPartnerAccessService({ dbPool: pool, secret: crypto.randomBytes(32).toString("hex"), signToken() {} });
  const organization = (await service.createOrganization({ name: "Local acceptance fixtures", allowedEmailDomains: ["example.test"] }, "local-fixture")).organization;
  const ios = { configured: true, async enroll(email) {
    if (email.startsWith("failure")) throw new Error("Mocked provider failure");
    return { testerId: "local-fixture", state: "INVITED" };
  }, async refresh() { return { state: "ACCEPTED" }; } };
  const android = { configured: true, async enroll() { return { state: "OPT_IN_REQUIRED" }; } };
  const invitations = createTesterInvitationService({ dbPool: pool, partnerAccessService: service, secret: crypto.randomBytes(32).toString("hex"),
    env: { ZIPPI_TESTER_INVITES_ENABLED: "true", ZIPPI_TESTER_ORGANIZATION_ID: organization.id }, providers: { ios, android },
    mailAdapter: { configured: true, async sendInstructions({ email }) { if (!email.endsWith("@example.test")) throw new Error("Fixture email only"); return { id: "local-message" }; } },
  });
  const app = express(); app.use(helmet()); app.use(express.json({ limit: "16kb" })); app.use(express.urlencoded({ extended: false, limit: "16kb" }));
  app.use("/admin", createAdminDashboardRouter({ dbPool: pool, adminSecret: process.env.TESTER_DEV_ADMIN_SECRET,
    sessionSecret: crypto.randomBytes(32).toString("hex"), partnerAccessService: service, testerInvitationService: invitations }));
  const server = app.listen(4318, "127.0.0.1", () => console.log("Local mocked invitation dashboard: http://localhost:4318/admin/partner-access"));
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(async () => { await pool.end(); await setup.query(`drop schema ${schema} cascade`); await setup.end(); process.exit(0); }));
}
main().catch(() => { console.error("Local invitation harness could not start."); process.exitCode = 1; });
