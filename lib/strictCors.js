const DEFAULT_ALLOWED_ORIGINS = ["https://www.heyzippi.com", "https://heyzippi.com"];

function parseAllowedOrigins(value) {
  const configured = String(value || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  return new Set(configured.length ? configured : DEFAULT_ALLOWED_ORIGINS);
}

function appendVary(res, value) {
  const current = String(res.getHeader("Vary") || "");
  const values = current.split(",").map((item) => item.trim()).filter(Boolean);
  if (!values.some((item) => item.toLowerCase() === value.toLowerCase())) values.push(value);
  res.setHeader("Vary", values.join(", "));
}

function createStrictCorsMiddleware(options = {}) {
  const allowedOrigins = parseAllowedOrigins(options.allowedOrigins);
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
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Request-ID");
    res.setHeader("Access-Control-Max-Age", "600");
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  };
}

module.exports = { DEFAULT_ALLOWED_ORIGINS, createStrictCorsMiddleware, parseAllowedOrigins };
