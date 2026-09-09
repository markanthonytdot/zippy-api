// Isolated local Partner Access server. No supplier, AI, payment or real email calls.
// Use only an isolated loopback PostgreSQL database with migration 013 applied.
const crypto = require("node:crypto");
const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const { createPartnerAccessService, createDevelopmentMailAdapter } = require("../lib/partnerAccess");
const { registerPartnerAccessRoutes, createPartnerAccessEnforcement } = require("../lib/partnerAccessRoutes");
const { createAdminDashboardRouter } = require("../lib/adminDashboard");

async function main() {
  if (String(process.env.NODE_ENV || "").trim().toLowerCase() === "production" || String(process.env.AUTH_MODE || "").trim().toLowerCase() === "prod") throw new Error("Local Partner Access runtime is disabled in production.");
  const url = new URL(process.env.PARTNER_DEV_DATABASE_URL || "postgres://marks@127.0.0.1:55432/postgres");
  if (!["postgres:", "postgresql:"].includes(url.protocol) || !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) throw new Error("An isolated loopback PostgreSQL database is required.");
  const adminSecret = process.env.PARTNER_DEV_ADMIN_SECRET;
  if (!adminSecret) throw new Error("Set PARTNER_DEV_ADMIN_SECRET to a local-only admin key.");
  const pool = new Pool({ connectionString: url.toString(), ssl: false });
  const jwtSecret = process.env.PARTNER_DEV_JWT_SECRET || crypto.randomBytes(32).toString("hex");
  const sessionSecret = crypto.randomBytes(32).toString("hex");
  const { SignJWT, jwtVerify } = await import("jose");
  const key = new TextEncoder().encode(jwtSecret);
  const mail = createDevelopmentMailAdapter({ enabled: true, fixedCode: "314159" });
  const service = createPartnerAccessService({ dbPool: pool, secret: jwtSecret, mailAdapter: mail,
    signToken: (subject, claims) => new SignJWT({ ...claims, uid: subject }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setSubject(subject).setIssuer("zippy-api").setAudience("zippy-ios").setIssuedAt().setExpirationTime("30d").sign(key),
  });
  const existing = await service.list();
  let organization = existing.organizations.find(row => row.name === "Porter Preview Fixture");
  if (!organization) organization = (await service.createOrganization({ name: "Porter Preview Fixture", allowedEmailDomains: ["porter.test"] }, "local-fixture")).organization;
  if (!existing.people.some(row => row.email === "preview@porter.test")) await service.createPerson({ email: "preview@porter.test", organizationId: organization.id, durationDays: 7 }, "local-fixture");

  const app = express();
  app.use(helmet()); app.use(express.json({ limit: "16kb" })); app.use(express.urlencoded({ extended: false, limit: "16kb" }));
  app.use(async (req, _res, next) => {
    try {
      const token = String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i)?.[1];
      if (token) {
        req.authClaims = (await jwtVerify(token, key, { issuer: "zippy-api", audience: "zippy-ios", algorithms: ["HS256"] })).payload;
        req.userId = req.authClaims.sub; req.userIdVerified = true;
      }
    } catch { /* Invalid bearer is rejected by the same protected route contracts. */ }
    next();
  });
  const required = process.env.ZIPPI_PARTNER_ACCESS_REQUIRED === "true";
  registerPartnerAccessRoutes(app, { service, required, verifyUser: async (req, res) => {
    if (req.userIdVerified) return req.userId;
    res.status(401).json({ ok: false, error: "invalid_auth" }); return null;
  } });
  app.use(createPartnerAccessEnforcement({ service, required }));
  app.get("/__dev/mailbox", (req, res) => {
    res.set("Cache-Control", "no-store");
    const message = mail.read(req.query.email);
    res.json({ ok: true, message });
  });
  app.get(["/admin", "/admin/"], (_req, res) => res.redirect("/admin/partner-access"));
  app.use("/admin", createAdminDashboardRouter({ dbPool: pool, adminSecret, sessionSecret, partnerAccessService: service }));
  app.get("/health", (_req, res) => res.json({ ok: true, localOnly: true }));
  app.all(["/v1/flights/search", "/v1/hotels/search", "/v1/responses", "/v1/checkout/confirm"], (_req, res) => res.json({ ok: true, localOnly: true, results: [] }));
  const port = Number(process.env.PARTNER_DEV_PORT || 4317);
  const server = app.listen(port, "127.0.0.1", () => console.log(`Partner Access LOCAL ONLY: http://127.0.0.1:${port}/admin/partner-access; fixture preview@porter.test; mailbox /__dev/mailbox?email=preview%40porter.test`));
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(() => pool.end().then(() => process.exit(0))));
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
