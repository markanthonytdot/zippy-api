const DEFAULT_ROUNDING_RULES = Object.freeze({
  CAD: 500,
  USD: 500,
  EUR: 500,
  COP: 50_000,
});

const SUPPORTED_CUSTOMER_CURRENCIES = Object.freeze(["CAD", "USD", "EUR", "COP"]);

const DEFAULT_CURRENCY_REGION_DEFAULTS = Object.freeze({
  DEFAULT: "USD",
  CA: "CAD",
  US: "USD",
  CO: "COP",
  EU: "EUR",
});

const EURO_ZONE_COUNTRY_CODES = Object.freeze([
  "AD", "AT", "BE", "CY", "DE", "EE", "ES", "FI", "FR", "GR",
  "HR", "IE", "IT", "LT", "LU", "LV", "MC", "MT", "NL", "PT",
  "SI", "SK", "SM", "VA",
]);

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

function normalizeCurrencyCode(value, field = "currency") {
  const code = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(code)) throw pricingConfigError(field);
  return code;
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

function normalizeCurrencySettingsConfig(candidate, fallback = {}) {
  const source = candidate && typeof candidate === "object" && !Array.isArray(candidate) ? candidate : {};
  const currenciesSource = source.currencies && typeof source.currencies === "object" && !Array.isArray(source.currencies)
    ? source.currencies
    : {};
  const fallbackCurrencies = fallback.currencies && typeof fallback.currencies === "object" && !Array.isArray(fallback.currencies)
    ? fallback.currencies
    : {};
  const result = { currencies: {}, defaultsByRegion: {} };

  for (const code of SUPPORTED_CUSTOMER_CURRENCIES) {
    const candidateCurrency = currenciesSource[code];
    const fallbackCurrency = fallbackCurrencies[code] || {};
    const enabledRaw = candidateCurrency?.enabled ?? fallbackCurrency.enabled;
    if (typeof enabledRaw !== "boolean") throw pricingConfigError(`currencies.${code}.enabled`);
    const roundingRaw = candidateCurrency?.roundingIncrementMinor ?? fallbackCurrency.roundingIncrementMinor;
    const roundingIncrementMinor = Number(roundingRaw);
    if (!Number.isSafeInteger(roundingIncrementMinor) || roundingIncrementMinor <= 0 || roundingIncrementMinor > 10_000_000) {
      throw pricingConfigError(`currencies.${code}.roundingIncrementMinor`);
    }
    result.currencies[code] = { enabled: enabledRaw, roundingIncrementMinor };
  }

  const defaultsSource = source.defaultsByRegion && typeof source.defaultsByRegion === "object" && !Array.isArray(source.defaultsByRegion)
    ? source.defaultsByRegion
    : {};
  const fallbackDefaults = fallback.defaultsByRegion && typeof fallback.defaultsByRegion === "object" && !Array.isArray(fallback.defaultsByRegion)
    ? fallback.defaultsByRegion
    : DEFAULT_CURRENCY_REGION_DEFAULTS;

  for (const region of Object.keys(DEFAULT_CURRENCY_REGION_DEFAULTS)) {
    const currency = normalizeCurrencyCode(
      defaultsSource[region] ?? fallbackDefaults[region] ?? DEFAULT_CURRENCY_REGION_DEFAULTS[region],
      `defaultsByRegion.${region}`
    );
    if (!SUPPORTED_CUSTOMER_CURRENCIES.includes(currency)) {
      throw pricingConfigError(`defaultsByRegion.${region}`);
    }
    result.defaultsByRegion[region] = currency;
  }

  const enabledCurrencies = SUPPORTED_CUSTOMER_CURRENCIES.filter((code) => result.currencies[code].enabled);
  if (!enabledCurrencies.length) throw pricingConfigError("currencies");
  for (const [region, code] of Object.entries(result.defaultsByRegion)) {
    if (!result.currencies[code]?.enabled) {
      throw pricingConfigError(`defaultsByRegion.${region}`);
    }
  }

  return result;
}

function hasCompleteFlightConfig(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
  return Object.keys(FLIGHT_CONFIG_FIELDS).every((field) => Object.hasOwn(candidate, field))
    && candidate.roundingRules
    && typeof candidate.roundingRules === "object";
}

function hasCompleteCurrencySettingsConfig(candidate) {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
  const currencies = candidate.currencies;
  const defaultsByRegion = candidate.defaultsByRegion;
  return Boolean(currencies && typeof currencies === "object" && !Array.isArray(currencies))
    && Boolean(defaultsByRegion && typeof defaultsByRegion === "object" && !Array.isArray(defaultsByRegion))
    && SUPPORTED_CUSTOMER_CURRENCIES.every((code) => {
      const row = currencies[code];
      return row && typeof row === "object"
        && typeof row.enabled === "boolean"
        && Number.isSafeInteger(Number(row.roundingIncrementMinor));
    })
    && Object.keys(DEFAULT_CURRENCY_REGION_DEFAULTS).every((region) => typeof defaultsByRegion[region] === "string");
}

function createVersionedConfigResolver(options = {}) {
  const {
    product,
    dbPool,
    environment = "test",
    fallbackConfig,
    log = console,
    normalizeConfig,
    hasCompleteConfig,
  } = options;
  const normalizedFallback = normalizeConfig(fallbackConfig);

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
          where product = $2 and environment = $1 and status = 'active'
          order by version desc limit 1`,
        [environment, product]
      );
    } catch (error) {
      if (error.code !== "42P01") {
        log.warn?.(`[${product}] centralized config read failed; using environment fallback`, error.message);
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
      if (!hasCompleteConfig(active.config)) throw pricingConfigError("config");
      return {
        source: "centralized_active",
        version: Number(active.version),
        environment,
        config: normalizeConfig(active.config),
        activatedAt: active.activated_at || null,
      };
    } catch (error) {
      log.warn?.(`[${product}] active centralized config is invalid; using environment fallback`, error.field || error.message);
      return {
        source: "environment_fallback",
        version: null,
        environment,
        config: normalizedFallback,
        activatedAt: null,
      };
    }
  }

  return { resolve, fallbackConfig: normalizedFallback, environment, product };
}

function createFlightPricingConfigResolver(options = {}) {
  return createVersionedConfigResolver({
    ...options,
    product: "flights",
    normalizeConfig: normalizeFlightPricingConfig,
    hasCompleteConfig: hasCompleteFlightConfig,
  });
}

function createCurrencySettingsResolver(options = {}) {
  return createVersionedConfigResolver({
    ...options,
    product: "currencies",
    normalizeConfig: normalizeCurrencySettingsConfig,
    hasCompleteConfig: hasCompleteCurrencySettingsConfig,
  });
}

function mergeFlightPricingWithCurrencySettings(flightConfig, currencySettings) {
  const normalizedFlight = normalizeFlightPricingConfig(flightConfig);
  const normalizedCurrencySettings = normalizeCurrencySettingsConfig(currencySettings, defaultCurrencySettingsConfig());
  return {
    ...normalizedFlight,
    roundingRules: SUPPORTED_CUSTOMER_CURRENCIES.reduce((acc, code) => {
      acc[code] = normalizedCurrencySettings.currencies[code].roundingIncrementMinor;
      return acc;
    }, {}),
  };
}

function isCurrencyEnabled(currencySettings, currency) {
  const normalized = normalizeCurrencySettingsConfig(currencySettings, defaultCurrencySettingsConfig());
  return Boolean(normalized.currencies[normalizeCurrencyCode(currency)]?.enabled);
}

function resolveCustomerCurrency(options = {}) {
  const {
    currencySettings,
    requestedCurrency = "",
    countryCode = "",
  } = options;
  const normalized = normalizeCurrencySettingsConfig(currencySettings, defaultCurrencySettingsConfig());
  const requested = String(requestedCurrency || "").trim().toUpperCase();
  if (SUPPORTED_CUSTOMER_CURRENCIES.includes(requested) && normalized.currencies[requested]?.enabled) {
    return { currency: requested, source: "requested" };
  }

  const country = String(countryCode || "").trim().toUpperCase();
  const regionKey = country && EURO_ZONE_COUNTRY_CODES.includes(country)
    ? "EU"
    : (country && Object.hasOwn(normalized.defaultsByRegion, country) ? country : "DEFAULT");
  const regionCurrency = normalized.defaultsByRegion[regionKey];
  if (regionCurrency && normalized.currencies[regionCurrency]?.enabled) {
    return { currency: regionCurrency, source: `default:${regionKey.toLowerCase()}` };
  }

  const firstEnabled = SUPPORTED_CUSTOMER_CURRENCIES.find((code) => normalized.currencies[code]?.enabled) || "USD";
  return { currency: firstEnabled, source: "default:first_enabled" };
}

function defaultCurrencySettingsConfig() {
  return {
    currencies: SUPPORTED_CUSTOMER_CURRENCIES.reduce((acc, code) => {
      acc[code] = {
        enabled: true,
        roundingIncrementMinor: DEFAULT_ROUNDING_RULES[code],
      };
      return acc;
    }, {}),
    defaultsByRegion: { ...DEFAULT_CURRENCY_REGION_DEFAULTS },
  };
}

module.exports = {
  DEFAULT_CURRENCY_REGION_DEFAULTS,
  DEFAULT_ROUNDING_RULES,
  EURO_ZONE_COUNTRY_CODES,
  FLIGHT_CONFIG_FIELDS,
  SUPPORTED_CUSTOMER_CURRENCIES,
  createCurrencySettingsResolver,
  createFlightPricingConfigResolver,
  defaultCurrencySettingsConfig,
  hasCompleteFlightConfig,
  hasCompleteCurrencySettingsConfig,
  isCurrencyEnabled,
  mergeFlightPricingWithCurrencySettings,
  normalizeCurrencySettingsConfig,
  normalizeFlightPricingConfig,
  normalizeRoundingRules,
  resolveCustomerCurrency,
};
