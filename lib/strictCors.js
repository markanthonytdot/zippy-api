const DEFAULT_ALLOWED_ORIGINS = ["https://www.heyzippi.com", "https://heyzippi.com"];
const BARE_PAGES_TEST_ORIGIN = "https://heyzippi-website-test.pages.dev";
const PRIVATE_PAGES_TEST_ORIGINS = [
  "https://main.heyzippi-website-test.pages.dev",
  "https://test.heyzippi-website-test.pages.dev",
];

function normalizePrivateStagingOrigins(origins) {
  const hasPrivateStaging = origins.has(BARE_PAGES_TEST_ORIGIN)
    || PRIVATE_PAGES_TEST_ORIGINS.some((origin) => origins.has(origin));
  if (!hasPrivateStaging) return origins;
  const normalized = new Set(origins);
  normalized.delete(BARE_PAGES_TEST_ORIGIN);
  for (const origin of PRIVATE_PAGES_TEST_ORIGINS) normalized.add(origin);
  return normalized;
}

function parseAllowedOrigins(value) {
  const configured = String(value || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  return normalizePrivateStagingOrigins(new Set(configured.length ? configured : DEFAULT_ALLOWED_ORIGINS));
}

function appendVary(res, value) {
  const current = String(res.getHeader("Vary") || "");
  const values = current.split(",").map((item) => item.trim()).filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  res.setHeader("Vary", values.join(", "));
}

function createStrictCorsMiddleware(options = {}) {
  const allowedOrigins = parseAllowedOrigins(options.allowedOrigins);
  const allowedMethods = String(options.allowedMethods || "POST, OPTIONS");
  return function strictCors(req, res, next) {
    const origin = String(req.headers?.origin || "").trim();
    if (!origin) return next();

    appendVary(res, "Origin");
    if (!allowedOrigins.has(origin)) {
      if (req.method === "OPTIONS") {
        return res.status(403).json({ ok: false, code: "cors_origin_denied", error: "Origin is not allowed." });
      }
      return next();
    }

    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", allowedMethods);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, X-User-ID");
    res.setHeader("Access-Control-Max-Age", "600");
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  };
}

module.exports = { DEFAULT_ALLOWED_ORIGINS, createStrictCorsMiddleware, parseAllowedOrigins };
