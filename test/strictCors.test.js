const test = require("node:test");
const assert = require("node:assert/strict");
const { createStrictCorsMiddleware, parseAllowedOrigins } = require("../lib/strictCors");

function runMiddleware({ origin, method = "OPTIONS", allowedOrigins, allowedMethods } = {}) {
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
  createStrictCorsMiddleware({ allowedOrigins, allowedMethods })(req, res, () => { result.next = true; });
  return result;
}

test("flight search CORS defaults to only canonical Zippi web origins", () => {
  assert.deepEqual([...parseAllowedOrigins()], ["https://www.heyzippi.com", "https://heyzippi.com"]);
  const allowed = runMiddleware({ origin: "https://www.heyzippi.com" });
  assert.equal(allowed.status, 204);
  assert.equal(allowed.ended, true);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://www.heyzippi.com");
  assert.equal(allowed.headers.get("access-control-allow-headers"), "Content-Type, X-Request-ID, X-User-ID");

  const denied = runMiddleware({ origin: "https://evil.example" });
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.has("access-control-allow-origin"), false);
});

test("CORS can expose centralized exchange-rate reads to Web staging", () => {
  const allowed = runMiddleware({
    origin: "https://test.heyzippi-website-test.pages.dev",
    method: "GET",
    allowedOrigins: "https://www.heyzippi.com,https://heyzippi-website-test.pages.dev",
    allowedMethods: "GET, POST, OPTIONS",
  });
  assert.equal(allowed.next, true);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://test.heyzippi-website-test.pages.dev");
  assert.equal(allowed.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
});

test("CORS allows configured origins and does not interfere with non-browser requests", () => {
  const configured = runMiddleware({ origin: "https://preview.heyzippi.com", method: "POST", allowedOrigins: "https://preview.heyzippi.com" });
  assert.equal(configured.next, true);
  assert.equal(configured.headers.get("access-control-allow-origin"), "https://preview.heyzippi.com");
  assert.match(configured.headers.get("access-control-allow-headers"), /X-User-ID/);

  const noOrigin = runMiddleware({ method: "POST" });
  assert.equal(noOrigin.next, true);
  assert.equal(noOrigin.headers.has("access-control-allow-origin"), false);
});

test("CORS maps the bare Pages test hostname to the private branch preview origin", () => {
  assert.deepEqual([...parseAllowedOrigins("https://www.heyzippi.com,https://heyzippi-website-test.pages.dev")], [
    "https://www.heyzippi.com",
    "https://main.heyzippi-website-test.pages.dev",
    "https://test.heyzippi-website-test.pages.dev",
  ]);

  const mainPreview = runMiddleware({
    origin: "https://main.heyzippi-website-test.pages.dev",
    allowedOrigins: "https://www.heyzippi.com,https://heyzippi-website-test.pages.dev",
  });
  assert.equal(mainPreview.status, 204);
  assert.equal(mainPreview.headers.get("access-control-allow-origin"), "https://main.heyzippi-website-test.pages.dev");

  const testPreview = runMiddleware({
    origin: "https://test.heyzippi-website-test.pages.dev",
    allowedOrigins: "https://www.heyzippi.com,https://heyzippi-website-test.pages.dev",
  });
  assert.equal(testPreview.status, 204);
  assert.equal(testPreview.headers.get("access-control-allow-origin"), "https://test.heyzippi-website-test.pages.dev");

  const bareProjectHost = runMiddleware({
    origin: "https://heyzippi-website-test.pages.dev",
    allowedOrigins: "https://www.heyzippi.com,https://heyzippi-website-test.pages.dev",
  });
  assert.equal(bareProjectHost.status, 403);
  assert.equal(bareProjectHost.headers.has("access-control-allow-origin"), false);
});

test("CORS keeps protected staging aliases together when one alias is configured", () => {
  assert.deepEqual([...parseAllowedOrigins("https://www.heyzippi.com,https://main.heyzippi-website-test.pages.dev")], [
    "https://www.heyzippi.com",
    "https://main.heyzippi-website-test.pages.dev",
    "https://test.heyzippi-website-test.pages.dev",
  ]);

  const testPreview = runMiddleware({
    origin: "https://test.heyzippi-website-test.pages.dev",
    allowedOrigins: "https://www.heyzippi.com,https://main.heyzippi-website-test.pages.dev",
  });
  assert.equal(testPreview.status, 204);
  assert.equal(testPreview.headers.get("access-control-allow-origin"), "https://test.heyzippi-website-test.pages.dev");
});
