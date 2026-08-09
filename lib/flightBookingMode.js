const MODES = new Set(["disabled", "test", "live"]);

function enabled(value) {
  return ["1", "true", "yes"].includes(String(value || "").trim().toLowerCase());
}

function stripeMode(value) {
  const key = String(value || "").trim();
  if (!key) return "missing";
  if (key.startsWith("sk_test_")) return "test";
  if (key.startsWith("sk_live_")) return "live";
  return "unknown";
}

function stripePublishableMode(value) {
  const key = String(value || "").trim();
  if (!key) return "missing";
  if (key.startsWith("pk_test_")) return "test";
  if (key.startsWith("pk_live_")) return "live";
  return "unknown";
}

function duffelMode(value) {
  const token = String(value || "").trim();
  if (!token) return "missing";
  if (token.startsWith("duffel_test_")) return "test";
  if (token.startsWith("duffel_live_")) return "live";
  return "unknown";
}

function resolveFlightBookingMode(environment = process.env) {
  const requestedMode = String(environment.FLIGHT_BOOKING_MODE || "disabled").trim().toLowerCase();
  const mode = MODES.has(requestedMode) ? requestedMode : "disabled";
  const invalidMode = requestedMode !== mode;
  const publicCheckoutEnabled = enabled(environment.FLIGHT_PUBLIC_CHECKOUT_ENABLED);
  const internalLiveEnabled = enabled(environment.FLIGHT_INTERNAL_LIVE_BOOKING_ENABLED);
  const testEnabled = enabled(environment.FLIGHT_TEST_BOOKING_ENABLED);

  const testStripeKey = String(environment.FLIGHT_STRIPE_TEST_SECRET_KEY || environment.STRIPE_SECRET_KEY || "").trim();
  const liveStripeKey = String(environment.FLIGHT_STRIPE_LIVE_SECRET_KEY || "").trim();
  const testWebhookSecret = String(environment.FLIGHT_STRIPE_TEST_WEBHOOK_SECRET || environment.STRIPE_WEBHOOK_SECRET || "").trim();
  const liveWebhookSecret = String(environment.FLIGHT_STRIPE_LIVE_WEBHOOK_SECRET || "").trim();
  const testPublishableKey = String(environment.FLIGHT_STRIPE_TEST_PUBLISHABLE_KEY || "").trim();
  const livePublishableKey = String(environment.FLIGHT_STRIPE_LIVE_PUBLISHABLE_KEY || "").trim();
  const testDuffelToken = String(environment.DUFFEL_FLIGHTS_TEST_BOOKING_TOKEN || environment.DUFFEL_FLIGHTS_BOOKING_TOKEN || "").trim();
  const liveDuffelToken = String(environment.DUFFEL_FLIGHTS_LIVE_BOOKING_TOKEN || "").trim();

  const stripeKey = mode === "test" ? testStripeKey : mode === "live" ? liveStripeKey : "";
  const webhookSecret = mode === "test" ? testWebhookSecret : mode === "live" ? liveWebhookSecret : "";
  const publishableKey = mode === "test" ? testPublishableKey : mode === "live" ? livePublishableKey : "";
  const duffelToken = mode === "test" ? testDuffelToken : mode === "live" ? liveDuffelToken : "";
  const credentialModesMatch = mode !== "disabled"
    && stripeMode(stripeKey) === mode
    && duffelMode(duffelToken) === mode;
  const executionEnabled = mode === "test" ? testEnabled : mode === "live" ? internalLiveEnabled : false;
  const configured = !invalidMode && credentialModesMatch && Boolean(webhookSecret);
  const checkoutEnabled = configured && executionEnabled && !publicCheckoutEnabled;

  const issues = [];
  if (invalidMode) issues.push("invalid_booking_mode");
  if (mode === "disabled") issues.push("booking_mode_disabled");
  if (mode !== "disabled" && stripeMode(stripeKey) !== mode) issues.push("stripe_credential_mode_mismatch");
  if (mode !== "disabled" && duffelMode(duffelToken) !== mode) issues.push("duffel_credential_mode_mismatch");
  if (mode !== "disabled" && !webhookSecret) issues.push("stripe_webhook_secret_missing");
  if (mode === "test" && !testEnabled) issues.push("test_booking_not_enabled");
  if (mode === "live" && !internalLiveEnabled) issues.push("internal_live_booking_not_enabled");
  if (publicCheckoutEnabled) issues.push("public_checkout_must_remain_disabled");

  return Object.freeze({
    mode,
    stripeKey,
    webhookSecret,
    publishableKey,
    duffelToken,
    stripeCredentialMode: stripeMode(stripeKey),
    stripePublishableMode: stripePublishableMode(publishableKey),
    publishableConfigured: stripePublishableMode(publishableKey) === mode,
    duffelCredentialMode: duffelMode(duffelToken),
    configured,
    checkoutEnabled,
    publicCheckoutEnabled,
    internalLiveEnabled,
    testEnabled,
    issues,
  });
}

module.exports = { duffelMode, enabled, resolveFlightBookingMode, stripeMode, stripePublishableMode };
