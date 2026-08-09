const test = require("node:test");
const assert = require("node:assert/strict");
const {
  activateFlightPricingDraft,
  bookingSummary,
  buildFlightPricingPreview,
  createAdminSessionToken,
  rollbackFlightPricingVersion,
  sanitizeFlightPricingConfig,
  verifyAdminSessionToken,
} = require("../lib/adminDashboard");

const currentConfig = {
  fxMarginBps: 500,
  zippiMarkupBps: 700,
  minGrossMarginMinor: 1_599,
  zippiFeeMinor: 499,
  paymentProcessingPercentBps: 350,
  paymentProcessingFixedMinor: 30,
  paymentProcessingCrossBorderBps: 0,
  roundingRules: { CAD: 500, USD: 500, EUR: 500, COP: 50_000 },
};

test("admin sessions are signed, expire, and reject tampering", () => {
  const now = Date.parse("2026-08-08T12:00:00Z");
  const token = createAdminSessionToken("test-session-secret", now);
  assert.equal(verifyAdminSessionToken(token, "test-session-secret", now + 1_000)?.subject, "zippi-admin");
  assert.equal(verifyAdminSessionToken(`${token}x`, "test-session-secret", now + 1_000), null);
  assert.equal(verifyAdminSessionToken(token, "different-secret", now + 1_000), null);
  assert.equal(verifyAdminSessionToken(token, "test-session-secret", now + (9 * 60 * 60 * 1_000)), null);
  assert.equal(verifyAdminSessionToken(token, "", now), null);
});

test("flight admin preview uses the production two-sided pricing engine", () => {
  const preview = buildFlightPricingPreview({
    providerAmount: 200,
    providerCurrency: "USD",
    customerCurrency: "CAD",
    config: currentConfig,
  }, currentConfig, {
    base: "USD",
    rates: { USD: 1, CAD: 1.35 },
    source: "test_rates",
    updatedAt: "2026-08-08T12:00:00Z",
  });

  assert.equal(preview.previewOnly, true);
  assert.equal(preview.quote.provider.currency, "USD");
  assert.equal(preview.quote.provider.totalMinor, 20_000);
  assert.equal(preview.quote.customer.currency, "CAD");
  assert.equal(preview.quote.customer.lineItems.fxProtectionMinor, 1_350);
  assert.equal(preview.quote.customer.lineItems.zippiMarkupMinor, 1_985);
  assert.equal(preview.quote.customer.lineItems.zippiFeeMinor, 499);
  assert.equal(preview.quote.customer.totalMinor % 500, 0);
  assert.ok(preview.quote.customer.lineItems.estimatedGrossMarginMinor >= currentConfig.minGrossMarginMinor);
});

test("flight pricing drafts validate every configurable field", () => {
  assert.deepEqual(sanitizeFlightPricingConfig({}, currentConfig), currentConfig);
  assert.throws(
    () => sanitizeFlightPricingConfig({ ...currentConfig, zippiMarkupBps: 5_001 }, currentConfig),
    (error) => error.code === "invalid_pricing_config" && error.field === "zippiMarkupBps"
  );
  assert.throws(
    () => sanitizeFlightPricingConfig({ ...currentConfig, zippiFeeMinor: 4.99 }, currentConfig),
    (error) => error.code === "invalid_pricing_config" && error.field === "zippiFeeMinor"
  );
});

test("booking summaries keep provider and customer currencies separate", () => {
  const summary = bookingSummary({
    id: "session-1",
    offer_snapshot: { slices: [{ segments: [{ origin: { iata_code: "YYZ" }, destination: { iata_code: "LAX" } }] }] },
    customer_currency: "CAD",
    customer_total_minor: 40_000,
    provider_currency: "USD",
    provider_total_minor: 25_000,
    customer_estimated_processing_minor: 1_430,
    customer_estimated_gross_margin_minor: 4_570,
    booking_status: "confirmed",
    duffel_booking_reference: "TEST12",
    created_at: "2026-08-08T12:00:00Z",
    updated_at: "2026-08-08T12:01:00Z",
  });
  assert.equal(summary.route, "YYZ → LAX");
  assert.deepEqual(summary.customer, { currency: "CAD", totalMinor: 40_000 });
  assert.deepEqual(summary.provider, { currency: "USD", totalMinor: 25_000 });
  assert.equal(summary.profitPercent, 11.43);
});

function transactionalPool(handler) {
  const queries = [];
  const client = {
    async query(sql, params) {
      const text = String(sql);
      queries.push({ text, params });
      return handler(text, params);
    },
    release() {},
  };
  return { queries, pool: { connect: async () => client } };
}

test("draft activation archives history and creates a new active version", async () => {
  const { pool, queries } = transactionalPool((sql) => {
    if (sql.includes("status = 'draft'") && sql.includes("for update")) return { rows: [{ version: 2, config: currentConfig }] };
    if (sql.includes("coalesce(max(version)")) return { rows: [{ version: "3" }] };
    if (sql.includes("insert into pricing_configurations")) {
      return { rows: [{ version: 3, status: "active", config: currentConfig, based_on_version: 2 }] };
    }
    return { rows: [] };
  });
  const active = await activateFlightPricingDraft(pool, { environment: "test", draftVersion: 2, actor: "owner" });
  assert.equal(active.version, 3);
  assert.equal(active.based_on_version, 2);
  assert.ok(queries.some(({ text }) => text.includes("status = 'archived'") && text.includes("status = 'active'")));
  assert.equal(queries.at(-1).text, "commit");
});

test("rollback creates a new active version from immutable history", async () => {
  const { pool, queries } = transactionalPool((sql) => {
    if (sql.includes("for share")) return { rows: [{ version: 1, config: currentConfig }] };
    if (sql.includes("coalesce(max(version)")) return { rows: [{ version: "5" }] };
    if (sql.includes("insert into pricing_configurations")) {
      return { rows: [{ version: 5, status: "active", config: currentConfig, based_on_version: 1 }] };
    }
    return { rows: [] };
  });
  const active = await rollbackFlightPricingVersion(pool, { environment: "test", targetVersion: 1, actor: "owner" });
  assert.equal(active.version, 5);
  assert.equal(active.based_on_version, 1);
  assert.ok(queries.some(({ text }) => text.includes("status = 'archived'") && text.includes("status = 'active'")));
  assert.equal(queries.at(-1).text, "commit");
});
