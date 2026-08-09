const DEFAULT_ROUNDING_RULES = Object.freeze({
  CAD: 500,
  USD: 500,
  EUR: 500,
  COP: 50_000,
});

const FLIGHT_CONFIG_FIELDS = Object.freeze({
  fxMarginBps: [0, 3_000],
  zippiMarkupBps: [0, 5_000],
  minGrossMarginMinor: [0, 1_000_000],
  zippiFeeMinor: [0, 100_000],
  paymentProcessingPercentBps: [0, 2_000],
  paymentProcessingFixedMinor: [0, 100_000],
  paymentProcessingCrossBorderBps: [0, 2_000],
});

function pricingConfigError(field) {
  const error = new Error(`Invalid ${field}`);
  error.code = "invalid_pricing_config";
  error.field = field;
  return error;
}

function normalizeRoundingRules(candidate, fallback = DEFAULT_ROUNDING_RULES) {
  const source = candidate && typeof candidate === "object" && !Array.isArray(candidate) ? candidate : {};
  const result = {};
  for (const currency of Object.keys(DEFAULT_ROUNDING_RULES)) {
    const value = Number(source[currency] ?? fallback?.[currency] ?? DEFAULT_ROUNDING_RULES[currency]);
    if (!Number.isSafeInteger(value) || value <= 0 || value > 10_000_000) {
      throw pricingConfigError(`roundingRules.${currency}`);
    }
    result[currency] = value;
  }
  return result;
}

function normalizeFlightPricingConfig(candidate, fallback = {}) {
  const result = {};
  for (const [field, [minimum, maximum]] of Object.entries(FLIGHT_CONFIG_FIELDS)) {
    const raw = candidate?.[field] ?? fallback?.[field];
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw pricingConfigError(field);
    }
    result[field] = value;
  }
  result.roundingRules = normalizeRoundingRules(candidate?.roundingRules, fallback?.roundingRules);
  return result;
}

function hasCompleteFlightConfig(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
  return Object.keys(FLIGHT_CONFIG_FIELDS).every((field) => Object.hasOwn(candidate, field))
    && candidate.roundingRules
    && typeof candidate.roundingRules === "object";
}

function createFlightPricingConfigResolver(options = {}) {
  const {
    dbPool,
    environment = "test",
    fallbackConfig,
    log = console,
  } = options;
  const normalizedFallback = normalizeFlightPricingConfig(fallbackConfig);

  async function resolve() {
    if (!dbPool) {
      return {
        source: "environment_fallback",
        version: null,
        environment,
        config: normalizedFallback,
        activatedAt: null,
      };
    }
    let result;
    try {
      result = await dbPool.query(
        `select version, config, activated_at
           from pricing_configurations
          where product = 'flights' and environment = $1 and status = 'active'
          order by version desc limit 1`,
        [environment]
      );
    } catch (error) {
      if (error.code !== "42P01") {
        log.warn?.("[Flight Pricing] centralized config read failed; using environment fallback", error.message);
      }
      return {
        source: "environment_fallback",
        version: null,
        environment,
        config: normalizedFallback,
        activatedAt: null,
      };
    }
    const active = result.rows[0];
    if (!active) {
      return {
        source: "environment_fallback",
        version: null,
        environment,
        config: normalizedFallback,
        activatedAt: null,
      };
    }
    try {
      if (!hasCompleteFlightConfig(active.config)) throw pricingConfigError("config");
      return {
        source: "centralized_active",
        version: Number(active.version),
        environment,
        config: normalizeFlightPricingConfig(active.config),
        activatedAt: active.activated_at || null,
      };
    } catch (error) {
      log.warn?.("[Flight Pricing] active centralized config is invalid; using environment fallback", error.field || error.message);
      return {
        source: "environment_fallback",
        version: null,
        environment,
        config: normalizedFallback,
        activatedAt: null,
      };
    }
  }

  return { resolve, fallbackConfig: normalizedFallback, environment };
}

module.exports = {
  DEFAULT_ROUNDING_RULES,
  FLIGHT_CONFIG_FIELDS,
  createFlightPricingConfigResolver,
  hasCompleteFlightConfig,
  normalizeFlightPricingConfig,
  normalizeRoundingRules,
};
