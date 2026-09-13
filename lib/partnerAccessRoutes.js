const express = require("express");
const { PartnerAccessError } = require("./partnerAccess");

function sendError(res, error) {
  const status = error instanceof PartnerAccessError ? error.status : 503;
  if (status === 429) res.setHeader("Retry-After", "60");
  return res.status(status).json({ ok: false, error: error instanceof PartnerAccessError ? error.code : "partner_access_unavailable" });
}
function route(work) {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try { await work(req, res); } catch (error) { sendError(res, error); }
  };
}
function registerPartnerAccessRoutes(app, { service, required = false, verifyUser }) {
  app.get("/partner-access/config", route(async (_req, res) => res.json({ ok: true, required })));
  app.post("/partner-access/request-code", route(async (req, res) => res.status(202).json(await service.requestCode({ ...req.body, ip: req.ip || req.socket?.remoteAddress }))));
  app.post("/partner-access/verify-code", route(async (req, res) => res.json(await service.verifyCode({ ...req.body, ip: req.ip || req.socket?.remoteAddress }))));
  app.get("/partner-access/status", route(async (req, res) => {
    const user = await verifyUser(req, res);
    if (!user) return;
    res.json(await service.status(req.authClaims));
  }));
}

function routeFeatures(req) {
  const path = String(req.originalUrl || req.path || "").split("?")[0].toLowerCase().replace(/\/+$/, "");
  const features = [];
  // Public image bytes carry no entitlement or travel inventory; native URL images can stay anonymous.
  if (path === "/v1/hotels/photo") return features;
  if (path.startsWith("/v1/flights") || path.startsWith("/flight/") || path === "/v1/intent/flight/parse") features.push("flights");
  if (req.method !== "GET" && (path.startsWith("/v1/bookings") || path.startsWith("/v1/checkout"))) features.push("flights");
  if (path.startsWith("/v1/hotels")) features.push("hotels");
  if (/\/(?:payment|checkout|booking)(?:\/|$)/.test(path) || /\/(?:book|selection\/quote)$/.test(path) || (req.method !== "GET" && path.startsWith("/v1/bookings")) || path === "/v1/hotels/quote") features.push("checkout");
  if (req.headers?.["x-zippi-feature"] === "combinedTrip") features.push("combinedTrip");
  return [...new Set(features)];
}
function hasUnverifiedPartnerHint(req) {
  try {
    const token = String(req.headers?.authorization || "").replace(/^Bearer\s+/i, "");
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
    return payload.auth_method === "partner_preview" || String(payload.sub || "").startsWith("partner:");
  } catch { return false; }
}
function createPartnerAccessEnforcement({ service, required = false }) {
  return async (req, res, next) => {
    const path = String(req.originalUrl || req.path || "").split("?")[0].toLowerCase().replace(/\/+$/, "");
    if (path === "/me/account" && req.method === "DELETE") return next();
    if (path.startsWith("/partner-access/") || path.startsWith("/auth/") || path.startsWith("/admin") || path.startsWith("/health") || path === "/version") return next();
    const features = routeFeatures(req);
    const protectedPreviewRoute = features.length || path === "/v1/responses";
    const claims = req.authClaims;
    const isPartner = claims?.auth_method === "partner_preview" || String(claims?.sub || "").startsWith("partner:");
    if (!isPartner) {
      // Unverified claims can only deny access, never establish identity/permission.
      if (hasUnverifiedPartnerHint(req)) return res.status(401).json({ ok: false, error: "invalid_auth" });
      if (required && protectedPreviewRoute && !req.userIdVerified) return res.status(401).json({ ok: false, error: "partner_access_required" });
      return next();
    }
    try {
      const status = await service.status(claims);
      req.partnerAccess = status;
      if (status.access !== "active") return res.status(403).json({ ok: false, error: "partner_access_unavailable", access: status.access });
      if (features.some(feature => status.features[feature] !== true)) return res.status(403).json({ ok: false, error: "partner_feature_unavailable" });
      return next();
    } catch (error) { return sendError(res, error); }
  };
}

function createPartnerAdminRouter({ service }) {
  const router = express.Router();
  // Mounted only after the existing admin signed-session middleware. Defense in depth.
  router.use((req, res, next) => {
    if (!req.zippiAdmin) return res.status(401).json({ ok: false, error: "admin_auth_required" });
    if (req.method !== "GET") {
      const expected = `${req.protocol}://${req.get("host")}`;
      if (req.get("origin") !== expected || !req.is("application/json")) return res.status(403).json({ ok: false, error: "admin_origin_required" });
    }
    return next();
  });
  router.get("/", route(async (_req, res) => res.json(await service.list())));
  router.post("/organizations", route(async (req, res) => res.status(201).json(await service.createOrganization(req.body, req.zippiAdmin.actor))));
  router.post("/people", route(async (req, res) => res.status(201).json(await service.createPerson(req.body, req.zippiAdmin.actor))));
  router.get("/people/:id/deletion", route(async (req, res) => res.json(await service.describeDeletion(req.params.id))));
  router.post("/people/:id/delete", route(async (req, res) => res.json(await service.deletePerson(req.params.id, req.body, req.zippiAdmin.actor))));
  for (const action of ["adjust", "extend", "revoke", "update"]) {
    router.post(`/people/:id/${action}`, route(async (req, res) => res.json(await service.changePerson(req.params.id, action, req.body, req.zippiAdmin.actor))));
  }
  return router;
}

module.exports = { registerPartnerAccessRoutes, createPartnerAccessEnforcement, createPartnerAdminRouter, routeFeatures, sendError };
