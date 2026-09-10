const { createDevelopmentMailAdapter, PartnerAccessError } = require("./partnerAccess");

function createResendMailAdapter(env, { fetchImpl = globalThis.fetch } = {}) {
  const apiKey = String(env.RESEND_API_KEY || "").trim();
  const from = String(env.ZIPPI_PARTNER_EMAIL_FROM || "").trim();
  if (!apiKey || !from || typeof fetchImpl !== "function") return createDevelopmentMailAdapter();
  async function deliver({ email, subject, text, idempotencyKey }) {
    try {
      const response = await fetchImpl("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json", ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}) },
        redirect: "error",
        signal: AbortSignal.timeout(15000),
        body: JSON.stringify({ from, to: [email], subject, text }),
      });
      if (!response.ok) throw new Error("delivery_failed");
      const result = await response.json();
      if (typeof result?.id !== "string" || !result.id.trim()) throw new Error("delivery_failed");
      return { id: result.id };
    } catch {
      // Provider responses can contain credentials, addresses or message content.
      // Never log or forward them, retry delivery, or fall back to another adapter.
      throw new PartnerAccessError(503, "mail_unavailable");
    }
  }
  return {
    configured: true,
    async send({ email, code, expiresInSeconds }) {
      await deliver({ email, subject: "Your Zippi Partner Preview code",
        text: `Your Zippi verification code is:\n\n${code}\n\nThis code expires in ${Math.floor(expiresInSeconds / 60)} minutes.\n\nIf you didn’t request this code, you can ignore this email.` });
    },
    sendInstructions: deliver,
  };
}
module.exports = { createResendMailAdapter };
