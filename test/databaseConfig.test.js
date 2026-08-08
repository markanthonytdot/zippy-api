const test = require("node:test");
const assert = require("node:assert/strict");
const { databaseSSLForURL } = require("../lib/databaseConfig");

test("disables migration TLS only for exact local database hostnames", () => {
  assert.equal(databaseSSLForURL("postgresql://user:pass@localhost:5432/zippi"), false);
  assert.equal(databaseSSLForURL("postgres://user:pass@127.0.0.1/zippi"), false);
  assert.equal(databaseSSLForURL("postgres://user:pass@[::1]/zippi"), false);
  assert.deepEqual(databaseSSLForURL("postgres://localhost.evil.example/zippi"), { rejectUnauthorized: false });
  assert.deepEqual(databaseSSLForURL("postgres://user:localhost@db.example/zippi"), { rejectUnauthorized: false });
});

test("rejects malformed or non-PostgreSQL database URLs", () => {
  assert.throws(() => databaseSSLForURL("not a url"), /valid PostgreSQL URL/);
  assert.throws(() => databaseSSLForURL("https://db.example/zippi"), /postgres or postgresql scheme/);
});
