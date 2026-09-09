const { createDevelopmentMailAdapter, PartnerAccessError } = require("./partnerAccess");

function createPartnerMailAdapter(env = process.env, { createTransport } = {}) {
  const production = String(env.AUTH_MODE || "").trim().toLowerCase() === "prod" || String(env.NODE_ENV || "").trim().toLowerCase() === "production";
  if (env.ZIPPI_PARTNER_MAIL_ADAPTER === "development") {
    return createDevelopmentMailAdapter({ enabled: true, production });
  }
  if (env.ZIPPI_PARTNER_MAIL_ADAPTER !== "smtp") return createDevelopmentMailAdapter();
  const host = String(env.ZIPPI_PARTNER_SMTP_HOST || "").trim();
  const user = String(env.ZIPPI_PARTNER_SMTP_USER || "").trim();
  const pass = String(env.ZIPPI_PARTNER_SMTP_PASSWORD || "");
  const from = String(env.ZIPPI_PARTNER_SMTP_FROM || "").trim();
  const port = Number(env.ZIPPI_PARTNER_SMTP_PORT || 465);
  if (!host || !user || !pass || !from || ![465, 587].includes(port)) return createDevelopmentMailAdapter();
  const transport = (createTransport || require("nodemailer").createTransport)({
    host, port, secure: port === 465, requireTLS: true, auth: { user, pass },
    tls: { minVersion: "TLSv1.2", rejectUnauthorized: true },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    logger: false, debug: false, disableFileAccess: true, disableUrlAccess: true,
  });
  return {
    configured: true,
    async send({ email, code, expiresInSeconds }) {
      try {
        await transport.sendMail({
          from, to: email, subject: "Your Zippi Partner Preview code",
          text: `Your Zippi verification code is ${code}.\n\nIt expires in ${Math.floor(expiresInSeconds / 60)} minutes and can be used once. If you did not request this code, ignore this email.`,
        });
      } catch { throw new PartnerAccessError(503, "mail_unavailable"); }
    },
  };
}
module.exports = { createPartnerMailAdapter };
