const { randomUUID } = require("node:crypto");
const { Pool } = require("pg");
const Stripe = require("stripe");
const { databaseSSLForURL } = require("../lib/databaseConfig");
const { buildConfirmation } = require("../lib/flightBooking");
const { createFlightRecoveryService } = require("../lib/flightRecovery");
const { createDuffelOrderLookup } = require("../lib/duffelOrderLookup");

function requiredEnvironment(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const databaseUrl = requiredEnvironment("DATABASE_URL");
  const stripeKey = requiredEnvironment("STRIPE_SECRET_KEY");
  const duffelToken = requiredEnvironment("DUFFEL_FLIGHTS_BOOKING_TOKEN");
  if (!stripeKey.startsWith("sk_test_")) throw new Error("Flight recovery requires a Stripe test secret key");
  if (!duffelToken.startsWith("duffel_test_")) throw new Error("Flight recovery requires a Duffel test token");
  const pool = new Pool({
    connectionString: databaseUrl,
    ssl: databaseSSLForURL(databaseUrl),
    connectionTimeoutMillis: 10_000,
  });
  const service = createFlightRecoveryService({
    dbPool: pool,
    stripe: new Stripe(stripeKey),
    duffelLookup: createDuffelOrderLookup({
      token: duffelToken,
      apiVersion: String(process.env.DUFFEL_API_VERSION || "v2"),
      timeoutMs: Math.max(1000, Number(process.env.FLIGHT_RECOVERY_DUFFEL_TIMEOUT_MS || 15_000)),
    }),
    buildConfirmation,
  });
  const workerId = String(process.env.RENDER_INSTANCE_ID || `flight-recovery-${process.pid}-${randomUUID()}`);
  const runOnce = process.env.FLIGHT_RECOVERY_RUN_ONCE === "1";
  const intervalMs = Math.max(5_000, Number(process.env.FLIGHT_RECOVERY_INTERVAL_MS || 30_000));
  let stopping = false;
  process.on("SIGTERM", () => { stopping = true; });
  process.on("SIGINT", () => { stopping = true; });
  try {
    do {
      const result = await service.runOnce({ workerId });
      console.log(`[flight-recovery] claimed=${result.claimed}`);
      if (!runOnce && !stopping) await new Promise((resolve) => setTimeout(resolve, intervalMs));
    } while (!runOnce && !stopping);
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(`[flight-recovery] failed: ${error.message}`);
  process.exitCode = 1;
});
