const express = require("express");
const { PartnerAccessError } = require("./partnerAccess");
const { SAFE_ERRORS } = require("./testerInvitations");
const ROUTE_ERRORS = new Set([...SAFE_ERRORS, "invalid_email", "invalid_platform", "tester_policy_not_configured", "tester_invitations_disabled",
  "email_domain_not_allowed", "invalid_organization", "invitation_not_found", "invitation_in_progress", "rate_limited", "tester_qa_restricted"]);
function createTesterInvitationRouter({ service }) {
  const router = express.Router();
  router.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: "admin_auth_required" });
    if (req.method !== "GET" && (req.get("origin") !== `${req.protocol}://${req.get("host")}` || !req.is("application/json"))) {
      return res.status(403).json({ ok: false, error: "admin_origin_required" });
    }
    next();
  });
  const route = work => async (req, res) => {
    try { res.json(await work(req)); }
    catch (error) {
      const safe = error instanceof PartnerAccessError && ROUTE_ERRORS.has(error.code);
      if (safe && error.status === 429) res.setHeader("Retry-After", "300");
      res.status(safe ? error.status : 503).json({ ok: false, error: safe ? error.code : "tester_invitations_unavailable" });
    }
  };
  // This context is minted after authenticated-admin/origin middleware, never from input.
  const context = () => ({ authenticatedAdmin: true });
  router.get("/", route(() => service.list(context())));
  router.post("/", route(req => service.run({ email: req.body?.email, platform: req.body?.platform, organizationId: req.body?.organizationId }, req.zippiAdmin.actor, "invite", context())));
  for (const action of ["retry", "resend", "apple-resend", "refresh"]) {
    router.post(`/:id/${action}`, route(req => service.run({ id: req.params.id }, req.zippiAdmin.actor, action, context())));
  }
  return router;
}
module.exports = { createTesterInvitationRouter };
