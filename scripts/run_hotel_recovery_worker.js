const { randomUUID } = require("node:crypto");
const { Pool } = require("pg");
const Stripe = require("stripe");
const { databaseSSLForURL } = require("../lib/databaseConfig");
const { createHotelDuffelBookingLookup } = require("../lib/hotelDuffelBookingLookup");
const { createHotelRecoveryService } = require("../lib/hotelRecovery");

function required(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredDuffelStaysToken(environment = process.env) {
  const value = String(environment.DUFFEL_STAYS_KEY || environment.DUFFEL_API_KEY || "").trim();
  if (!value) throw new Error("DUFFEL_STAYS_KEY or DUFFEL_API_KEY is required");
  return value;
}
async function main() {
  if (!["1", "true", "yes"].includes(String(process.env.HOTEL_TEST_BOOKING_ENABLED || "").toLowerCase())) {
    throw new Error("Hotel TEST booking must be explicitly enabled");
  }
  const databaseUrl = required("DATABASE_URL");
  const stripeKey = required("STRIPE_SECRET_KEY");
  const duffelToken = requiredDuffelStaysToken();
  if (!stripeKey.startsWith("sk_test_")) throw new Error("Hotel recovery requires a Stripe TEST key");
  if (!duffelToken.startsWith("duffel_test_")) throw new Error("Hotel recovery requires a Duffel TEST token");
  const pool = new Pool({ connectionString: databaseUrl, ssl: databaseSSLForURL(databaseUrl), connectionTimeoutMillis: 10_000 });
  const service = createHotelRecoveryService({
    dbPool: pool,
    stripe: new Stripe(stripeKey),
    duffelLookup: createHotelDuffelBookingLookup({ token: duffelToken, apiVersion: String(process.env.DUFFEL_API_VERSION || "v2") }),
  });
  const workerId = String(process.env.RENDER_INSTANCE_ID || `hotel-recovery-${process.pid}-${randomUUID()}`);
  const once = process.env.HOTEL_RECOVERY_RUN_ONCE === "1";
  const intervalMs = Math.max(5_000, Number(process.env.HOTEL_RECOVERY_INTERVAL_MS || 30_000));
  let stopping = false;
  process.on("SIGTERM", () => { stopping = true; });
  process.on("SIGINT", () => { stopping = true; });
  try {
    do {
      const result = await service.runOnce({ workerId });
      console.log(`[hotel-recovery] claimed=${result.claimed}`);
      if (!once && !stopping) await new Promise((resolve) => setTimeout(resolve, intervalMs));
    } while (!once && !stopping);
  } finally { await pool.end(); }
}
if (require.main === module) {
  main().catch((error) => { console.error(`[hotel-recovery] failed: ${error.message}`); process.exitCode = 1; });
}

module.exports = { requiredDuffelStaysToken };
