const test = require("node:test");
const assert = require("node:assert/strict");
const { createStrictCorsMiddleware, parseAllowedOrigins } = require("../lib/strictCors");

function runMiddleware({ origin, method = "OPTIONS", allowedOrigins } = {}) {
  const headers = new Map();
  const req = { method, headers: origin ? { origin } : {} };
  const result = { next: false, status: null, body: null, ended: false, headers };
  const res = {
    getHeader(name) { return headers.get(name.toLowerCase()); },
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    status(value) { result.status = value; return this; },
    json(value) { result.body = value; return this; },
    end() { result.ended = true; return this; },
  };
  createStrictCorsMiddleware({ allowedOrigins })(req, res, () => { result.next = true; });
  return result;
}

test("flight search CORS defaults to only canonical Zippi web origins", () => {
  assert.deepEqual([...parseAllowedOrigins()], ["https://www.heyzippi.com", "https://heyzippi.com"]);
  const allowed = runMiddleware({ origin: "https://www.heyzippi.com" });
  assert.equal(allowed.status, 204);
  assert.equal(allowed.ended, true);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://www.heyzippi.com");
  assert.equal(allowed.headers.get("access-control-allow-headers"), "Content-Type, X-Request-ID");

  const denied = runMiddleware({ origin: "https://evil.example" });
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.has("access-control-allow-origin"), false);
});

test("CORS allows configured origins and does not interfere with non-browser requests", () => {
  const configured = runMiddleware({ origin: "https://preview.heyzippi.com", method: "POST", allowedOrigins: "https://preview.heyzippi.com" });
  assert.equal(configured.next, true);
  assert.equal(configured.headers.get("access-control-allow-origin"), "https://preview.heyzippi.com");

  const noOrigin = runMiddleware({ method: "POST" });
  assert.equal(noOrigin.next, true);
  assert.equal(noOrigin.headers.has("access-control-allow-origin"), false);
});
