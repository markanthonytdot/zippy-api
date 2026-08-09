const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createCurrencySettingsResolver,
  defaultCurrencySettingsConfig,
  mergeFlightPricingWithCurrencySettings,
  normalizeCurrencySettingsConfig,
  createFlightPricingConfigResolver,
  normalizeFlightPricingConfig,
} = require("../lib/pricingConfig");

const fallback = {
  fxMarginBps: 500,
  zippiMarkupBps: 700,
  minGrossMarginMinor: 1_599,
  zippiFeeMinor: 499,
  paymentProcessingPercentBps: 350,
  paymentProcessingFixedMinor: 30,
  paymentProcessingCrossBorderBps: 0,
  roundingRules: { CAD: 500, USD: 500, EUR: 500, COP: 50_000 },
};

function resolverFor(rows) {
  const warnings = [];
  const dbPool = { query: async () => ({ rows: typeof rows === "function" ? rows() : rows }) };
  return {
    warnings,
    resolver: createFlightPricingConfigResolver({
      dbPool,
      environment: "test",
      fallbackConfig: fallback,
      log: { warn: (...args) => warnings.push(args) },
    }),
  };
}

function currencyResolverFor(rows) {
  const warnings = [];
  const dbPool = { query: async () => ({ rows: typeof rows === "function" ? rows() : rows }) };
  return {
    warnings,
    resolver: createCurrencySettingsResolver({
      dbPool,
      environment: "test",
      fallbackConfig: defaultCurrencySettingsConfig(),
      log: { warn: (...args) => warnings.push(args) },
    }),
  };
}

test("no active centralized config uses the known-good environment fallback", async () => {
  const { resolver } = resolverFor([]);
  const resolved = await resolver.resolve();
  assert.equal(resolved.source, "environment_fallback");
  assert.equal(resolved.version, null);
  assert.deepEqual(resolved.config, fallback);
});

test("a complete active config becomes authoritative", async () => {
  const active = { ...fallback, zippiMarkupBps: 800, minGrossMarginMinor: 1_999 };
  const { resolver } = resolverFor([{ version: "4", config: active, activated_at: "2026-08-08T12:00:00Z" }]);
  const resolved = await resolver.resolve();
  assert.equal(resolved.source, "centralized_active");
  assert.equal(resolved.version, 4);
  assert.equal(resolved.config.zippiMarkupBps, 800);
  assert.equal(resolved.config.minGrossMarginMinor, 1_999);
});

test("malformed active config fails safely back to environment values", async () => {
  const { resolver, warnings } = resolverFor([{ version: "5", config: { ...fallback, zippiMarkupBps: -1 } }]);
  const resolved = await resolver.resolve();
  assert.equal(resolved.source, "environment_fallback");
  assert.deepEqual(resolved.config, fallback);
  assert.equal(warnings.length, 1);
});

test("draft-only state does not affect live pricing", async () => {
  let activeRows = [];
  const { resolver } = resolverFor(() => activeRows);
  const before = await resolver.resolve();
  activeRows = [];
  const afterDraftSave = await resolver.resolve();
  assert.deepEqual(afterDraftSave, before);
});

test("activation affects subsequent reads while completed snapshots remain independent", async () => {
  let activeRows = [];
  const { resolver } = resolverFor(() => activeRows);
  const historicalSnapshot = (await resolver.resolve()).config;
  const active = { ...fallback, zippiMarkupBps: 900 };
  activeRows = [{ version: "7", config: active, activated_at: "2026-08-08T13:00:00Z" }];
  const subsequent = await resolver.resolve();
  assert.equal(subsequent.config.zippiMarkupBps, 900);
  assert.equal(historicalSnapshot.zippiMarkupBps, 700);
});

test("rollback-style activation restores old behavior as a new version", async () => {
  const restored = { ...fallback, zippiMarkupBps: 700 };
  const { resolver } = resolverFor([{ version: "9", config: restored, activated_at: "2026-08-08T14:00:00Z" }]);
  const resolved = await resolver.resolve();
  assert.equal(resolved.version, 9);
  assert.equal(resolved.config.zippiMarkupBps, 700);
});

test("concurrent pricing reads return complete stable snapshots", async () => {
  const active = { ...fallback, zippiFeeMinor: 599 };
  const { resolver } = resolverFor([{ version: "10", config: active, activated_at: "2026-08-08T15:00:00Z" }]);
  const results = await Promise.all(Array.from({ length: 25 }, () => resolver.resolve()));
  assert.ok(results.every((result) => result.version === 10 && result.config.zippiFeeMinor === 599));
});

test("rounding rules are validated as part of the authoritative config", () => {
  assert.equal(normalizeFlightPricingConfig(fallback).roundingRules.COP, 50_000);
  assert.throws(
    () => normalizeFlightPricingConfig({ ...fallback, roundingRules: { ...fallback.roundingRules, CAD: 0 } }),
    (error) => error.code === "invalid_pricing_config" && error.field === "roundingRules.CAD"
  );
});

test("currency settings resolve enabled currencies and shared rounding rules", async () => {
  const active = {
    currencies: {
      CAD: { enabled: true, roundingIncrementMinor: 500 },
      USD: { enabled: true, roundingIncrementMinor: 500 },
      EUR: { enabled: false, roundingIncrementMinor: 500 },
      COP: { enabled: true, roundingIncrementMinor: 50_000 },
    },
    defaultsByRegion: {
      DEFAULT: "USD",
      CA: "CAD",
      US: "USD",
      CO: "COP",
      EU: "USD",
    },
  };
  const { resolver } = currencyResolverFor([{ version: "2", config: active, activated_at: "2026-08-09T12:00:00Z" }]);
  const resolved = await resolver.resolve();
  assert.equal(resolved.source, "centralized_active");
  assert.equal(resolved.config.currencies.EUR.enabled, false);
  assert.equal(resolved.config.defaultsByRegion.CO, "COP");
});

test("currency settings merge becomes authoritative for final rounding", () => {
  const currencySettings = normalizeCurrencySettingsConfig({
    currencies: {
      CAD: { enabled: true, roundingIncrementMinor: 1_000 },
      USD: { enabled: true, roundingIncrementMinor: 500 },
      EUR: { enabled: true, roundingIncrementMinor: 500 },
      COP: { enabled: true, roundingIncrementMinor: 50_000 },
    },
    defaultsByRegion: {
      DEFAULT: "USD",
      CA: "CAD",
      US: "USD",
      CO: "COP",
      EU: "EUR",
    },
  }, defaultCurrencySettingsConfig());
  const merged = mergeFlightPricingWithCurrencySettings(fallback, currencySettings);
  assert.equal(merged.roundingRules.CAD, 1_000);
  assert.equal(merged.roundingRules.COP, 50_000);
});
