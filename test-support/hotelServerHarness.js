const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");

const serverPath = path.join(__dirname, "..", "server.js");
const serverRequire = createRequire(serverPath);
const jsonCopy = (value) => JSON.parse(JSON.stringify(value));
const noopMiddleware = () => (_req, _res, next) => next();

// Register the real server's middleware/routes without starting a socket, loading
// machine credentials, constructing database/payment clients, or using network.
// JWT cryptography is outside these route tests: a deterministic verifier lets us
// test the real optional/required-auth gates and ownership handoff independently.
function createServerHarness({ env = {}, providerResponse, now } = {}) {
  const layers = [];
  const providerCalls = [];
  const unexpectedCalls = [];
  const app = {
    set() {},
    listen() {},
    use(...args) {
      const mounted = typeof args[0] === "string" || Array.isArray(args[0]);
      const mounts = mounted ? [args.shift()].flat() : [""];
      layers.push({ mounts, handlers: args.flat(), method: null });
    },
  };
  for (const method of ["get", "post", "delete"]) {
    app[method] = (route, ...handlers) => layers.push({ mounts: [route], handlers, method: method.toUpperCase() });
  }
  const express = () => app;
  express.json = express.urlencoded = express.raw = noopMiddleware;
  class ForbiddenClient {
    constructor() { throw new Error("Route tests must not construct database or payment clients"); }
  }
  const context = {
    require(name) {
      if (name === "express") return express;
      if (name === "helmet") return noopMiddleware;
      if (name === "pg") return { Pool: ForbiddenClient };
      if (name === "stripe") return ForbiddenClient;
      if (name === "@google-cloud/translate") return { v2: { Translate: ForbiddenClient } };
      return serverRequire(name);
    },
    process: { env: { NODE_ENV: "test", AUTH_MODE: "prod", DUFFEL_STAYS_KEY: "duffel_test_fixture", JWT_SECRET: "route-test-only", ...env } },
    console: { log() {}, warn() {}, error() {} },
    URL, URLSearchParams, Buffer, TextEncoder, AbortController, setTimeout, clearTimeout,
    ...(now ? { Date: class extends Date { constructor(...args) { super(...(args.length ? args : [now()])); } static now() { return now(); } } } : {}),
    async fetch(url, options = {}) {
      // The server warms its display-FX cache on boot. Supply an empty local
      // response; this fixture never grants authority through an exchange rate.
      if (String(url) === "https://open.er-api.com/v6/latest/USD") {
        return { ok: true, status: 200, json: async () => ({}) };
      }
      const call = { url: String(url), options };
      providerCalls.push(call);
      if (providerResponse) {
        const result = await providerResponse(call);
        if (result !== undefined) {
          const status = result.httpStatus || 200;
          return { headers: new Headers(result.headers || {}), ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(result.httpStatus ? result.body : result) };
        }
      }
      unexpectedCalls.push(call.url);
      throw new Error("Unstubbed provider request rejected by route harness");
    },
  };
  vm.runInNewContext(`${fs.readFileSync(serverPath, "utf8")}\n
    getJose = async () => ({ jwtVerify: async (token) => {
      if (token !== "verified-fixture") throw new Error("Invalid fixture token");
      return { payload: { sub: "fixture-user" } };
    } });
    globalThis.testHooks = { hotelBookingService };
  `, context, { filename: serverPath });

  async function request(route, { method = "POST", body = {}, headers = {}, ip = "192.0.2.1", query = {}, signal } = {}) {
    const req = Object.assign(new (require("node:events").EventEmitter)(), { method, path: route, originalUrl: route, url: route, body, headers, ip, query, params: {} });
    const cancel = () => { req.aborted = true; req.emit("aborted"); };
    signal?.addEventListener("abort", cancel, { once: true });
    if (signal?.aborted) cancel();
    const response = { status: 200, body: null, headers: {}, finished: false };
    const res = Object.assign(new (require("node:events").EventEmitter)(), {
      status(value) { response.status = value; return this; },
      json(value) { response.body = jsonCopy(value); response.finished = true; return this; },
      end() { response.finished = true; return this; },
      setHeader(name, value) { response.headers[name.toLowerCase()] = value; },
      getHeader(name) { return response.headers[name.toLowerCase()]; },
    });
    for (const layer of layers) {
      if (layer.method && layer.method !== method) continue;
      const mount = layer.mounts.find((entry) => {
        if (!layer.method) return !entry || route === entry || route.startsWith(`${entry}/`);
        return new RegExp(`^${entry.replace(/:[^/]+/g, "[^/]+")}$`).test(route);
      });
      if (mount === undefined) continue;
      req.path = layer.method ? route : (route.slice(mount.length) || "/");
      if (layer.method) {
        const names = mount.split("/");
        const values = route.split("/");
        names.forEach((part, index) => { if (part.startsWith(":")) req.params[part.slice(1)] = values[index]; });
      }
      for (const handler of layer.handlers) {
        let advanced = false;
        await handler(req, res, () => { advanced = true; });
        if (response.finished || req.aborted) { signal?.removeEventListener("abort",cancel); return response; }
        assert.equal(advanced, true, `Unfinished middleware for ${method} ${route}`);
      }
    }
    assert.fail(`No handler completed ${method} ${route}`);
  }
  return { request, providerCalls, unexpectedCalls, bookingService: context.testHooks.hotelBookingService };
}

function stayResult(overrides = {}) {
  return {
    id: "srr_fixture", check_in_date: "2026-10-15", check_out_date: "2026-10-22",
    rooms: 1, guests: [{ type: "adult" }, { type: "adult" }],
    expires_at: "2099-01-01T00:00:00Z",
    cheapest_rate_total_amount: "840.00", cheapest_rate_currency: "USD",
    accommodation: {
      id: "acc_fixture", name: "Fixture Hotel", photos: [{ url: "https://images.example/hotel.jpg" }],
      rooms: [{ name: "King room", rates: [
        { id: "rat_fixture", total_amount: "840.00", total_currency: "USD", base_amount: "700.00", base_currency: "USD",
          tax_amount: "100.00", tax_currency: "USD", fee_amount: "40.00", fee_currency: "USD",
          due_at_accommodation_amount: "20.00", due_at_accommodation_currency: "USD", expires_at: "2099-01-01T00:00:00Z" },
        { id: "rat_alternative", total_amount: "900.00", total_currency: "USD" },
      ] }],
    },
    ...overrides,
  };
}


module.exports = { createServerHarness, stayResult };
