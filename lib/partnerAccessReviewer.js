// Dedicated App Review access is allowed only on the isolated Render staging service.
// These values identify the deployment, not credentials. Never log the code.
const REVIEW_EMAIL = "appreview@heyzippi.com";
const REVIEW_DIGEST_PREFIX = "review:v1:";
function createStagingReviewerAccess(env = process.env) {
  if (env.ZIPPI_PARTNER_REVIEW_ENABLED !== "true") return null;
  const expiresAt = Date.parse(env.ZIPPI_PARTNER_REVIEW_EXPIRES_AT || "");
  if (env.RENDER_SERVICE_ID !== "srv-dagq12ht0dsc73a7dm40" ||
      env.RENDER_EXTERNAL_HOSTNAME !== "zippi-partner-staging.onrender.com" ||
      !/^\d{6}$/.test(env.ZIPPI_PARTNER_REVIEW_CODE || "") || !Number.isFinite(expiresAt)) {
    throw new Error("Staging reviewer configuration is invalid.");
  }
  const code = env.ZIPPI_PARTNER_REVIEW_CODE;
  return Object.freeze({
    challenge(email, platform, personExpiresAt, now) {
      if (email !== REVIEW_EMAIL || platform !== "ios" || now >= expiresAt) return null;
      return { code, expiresAt: Math.min(expiresAt, new Date(personExpiresAt).getTime()) };
    },
  });
}
module.exports = { createStagingReviewerAccess, REVIEW_DIGEST_PREFIX };
