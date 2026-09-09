const test = require("node:test");
const assert = require("node:assert/strict");
const { createPartnerMailAdapter } = require("../lib/partnerAccessMail");

const env = {
  NODE_ENV: "production", ZIPPI_PARTNER_MAIL_ADAPTER: "resend",
  RESEND_API_KEY: "test-only-not-a-real-key", ZIPPI_PARTNER_EMAIL_FROM: "Zippi Partner Preview <preview@example.test>",
};
const message = { email: "approved@example.test", code: "482931", expiresInSeconds: 600 };

test("Resend sends a plain-text OTP through authenticated HTTPS with a bounded request", async () => {
  let sent;
  const mail = createPartnerMailAdapter(env, { fetchImpl: async (url, options) => {
    sent = { url, ...options }; return { ok: true, json: async () => ({ id: "mock-message-id" }) };
  } });
  assert.equal(mail.configured, true);
  await mail.send(message);
  assert.equal(sent.url, "https://api.resend.com/emails");
  assert.equal(sent.method, "POST");
  assert.equal(sent.headers.Authorization, `Bearer ${env.RESEND_API_KEY}`);
  assert.equal(sent.headers["Content-Type"], "application/json");
  assert.equal(sent.redirect, "error");
  assert.ok(sent.signal instanceof AbortSignal);
  assert.equal(sent.signal.aborted, false);
  assert.deepEqual(JSON.parse(sent.body), {
    from: env.ZIPPI_PARTNER_EMAIL_FROM, to: [message.email], subject: "Your Zippi Partner Preview code",
    text: "Your Zippi verification code is:\n\n482931\n\nThis code expires in 10 minutes.\n\nIf you didn’t request this code, you can ignore this email.",
  });
  assert.equal(sent.body.includes(env.RESEND_API_KEY), false);
});

test("missing Resend configuration fails closed without SMTP fallback or HTTP calls", async () => {
  for (const missing of [{ RESEND_API_KEY: " " }, { ZIPPI_PARTNER_EMAIL_FROM: "" }, { ZIPPI_PARTNER_MAIL_ADAPTER: "unknown" }]) {
    const mail = createPartnerMailAdapter({ ...env, ...missing }, {
      fetchImpl() { assert.fail("No network when configuration is incomplete"); },
      createTransport() { assert.fail("Resend must never fall back to SMTP"); },
    });
    assert.equal(mail.configured, false);
    await assert.rejects(mail.send(message), { status: 503, code: "mail_unavailable" });
  }
});

for (const status of [301, 400, 401, 403, 422, 429, 500, 503]) {
  test(`Resend HTTP ${status} is sanitized and never retried`, async () => {
    let calls = 0;
    const mail = createPartnerMailAdapter(env, { fetchImpl: async () => {
      calls++;
      return { ok: false, status, json() { assert.fail("Do not consume provider error details"); } };
    } });
    await assert.rejects(mail.send(message), error => error.status === 503 && error.code === "mail_unavailable" && error.message === "mail_unavailable" && !error.cause);
    assert.equal(calls, 1);
  });
}

test("network, timeout and malformed success failures share a sanitized delivery error", async () => {
  for (const fetchImpl of [
    async () => { throw new Error("sensitive provider details"); },
    async () => { throw new DOMException("sensitive timeout details", "TimeoutError"); },
    async () => ({ ok: true, json: async () => { throw new Error("invalid JSON"); } }),
    ...[null, {}, { id: " " }, { id: 123 }].map(result => async () => ({ ok: true, json: async () => result })),
  ]) {
    const mail = createPartnerMailAdapter(env, { fetchImpl });
    await assert.rejects(mail.send(message), error => error.status === 503 && error.code === "mail_unavailable" && error.message === "mail_unavailable" && !error.cause);
  }
});
