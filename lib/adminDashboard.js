const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const {
  buildPricingQuote,
  calculatePricing,
  currencyExponent,
} = require("./flightBooking");
const {
  DEFAULT_CURRENCY_REGION_DEFAULTS,
  FLIGHT_CONFIG_FIELDS,
  SUPPORTED_CUSTOMER_CURRENCIES,
  normalizeCurrencySettingsConfig,
  normalizeFlightPricingConfig,
} = require("./pricingConfig");

const ADMIN_COOKIE = "__Secure-zippi_admin_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signValue(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createAdminSessionToken(secret, now = Date.now(), actor = "admin") {
  if (!secret) throw new Error("Admin session secret is required.");
  const payload = base64url(JSON.stringify({
    version: 1,
    subject: "zippi-admin",
    actor: String(actor || "admin").slice(0, 120),
    issuedAt: now,
    expiresAt: now + SESSION_TTL_MS,
    nonce: crypto.randomBytes(16).toString("hex"),
  }));
  return `${payload}.${signValue(payload, secret)}`;
}

function verifyAdminSessionToken(token, secret, now = Date.now()) {
  if (!secret) return null;
  const [payload, signature, extra] = String(token || "").split(".");
  if (!payload || !signature || extra || !constantTimeEqual(signature, signValue(payload, secret))) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (decoded.version !== 1 || decoded.subject !== "zippi-admin") return null;
    if (!Number.isFinite(decoded.expiresAt) || decoded.expiresAt <= now) return null;
    return decoded;
  } catch (_) {
    return null;
  }
}

function cookieValue(req, name) {
  const raw = String(req.headers.cookie || "");
  for (const part of raw.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return decodeURIComponent(part.slice(separator + 1).trim());
  }
  return "";
}

function sanitizeFlightPricingConfig(candidate, fallback = {}) {
  return normalizeFlightPricingConfig(candidate, fallback);
}

function sanitizeCurrencySettingsConfig(candidate, fallback = {}) {
  return normalizeCurrencySettingsConfig(candidate, fallback);
}

function decimalAmount(value, currency) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 10_000_000) {
    const error = new Error("Provider cost must be a positive monetary amount.");
    error.code = "invalid_provider_amount";
    throw error;
  }
  return amount.toFixed(currencyExponent(currency));
}

function normalizeCurrency(value) {
  const currency = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(currency)) {
    const error = new Error("Currency must be a three-letter ISO code.");
    error.code = "invalid_currency";
    throw error;
  }
  return currency;
}

function buildFlightPricingPreview(input, currentConfig, exchangeRates) {
  const providerCurrency = normalizeCurrency(input?.providerCurrency || "USD");
  const customerCurrency = normalizeCurrency(input?.customerCurrency || "CAD");
  const providerAmount = decimalAmount(input?.providerAmount ?? 200, providerCurrency);
  const config = sanitizeFlightPricingConfig(input?.config, currentConfig);
  if (!exchangeRates?.rates) {
    const error = new Error("Exchange rates are temporarily unavailable.");
    error.code = "exchange_rate_unavailable";
    throw error;
  }

  const pricing = calculatePricing({
    base_amount: providerAmount,
    tax_amount: (0).toFixed(currencyExponent(providerCurrency)),
    total_amount: providerAmount,
    total_currency: providerCurrency,
  }, [], customerCurrency, config, exchangeRates);

  return {
    ok: true,
    previewOnly: true,
    config,
    exchangeRate: {
      rate: pricing.customerFxRate,
      source: pricing.customerFxSource,
      updatedAt: exchangeRates.updatedAt || null,
    },
    quote: buildPricingQuote(pricing),
  };
}

function itinerarySummary(offerSnapshot) {
  const slices = Array.isArray(offerSnapshot?.slices) ? offerSnapshot.slices : [];
  const airports = slices.map((slice) => {
    const segments = Array.isArray(slice?.segments) ? slice.segments : [];
    const first = segments[0] || {};
    const last = segments[segments.length - 1] || {};
    return {
      origin: String(first?.origin?.iata_code || slice?.origin?.iata_code || slice?.origin || "").trim(),
      destination: String(last?.destination?.iata_code || slice?.destination?.iata_code || slice?.destination || "").trim(),
    };
  }).filter(({ origin, destination }) => origin || destination);
  if (!airports.length) return "Route unavailable";
  if (airports.length === 1) return `${airports[0].origin || "?"} → ${airports[0].destination || "?"}`;
  return `${airports[0].origin || "?"} ⇄ ${airports[0].destination || airports[1].origin || "?"}`;
}

function bookingSummary(row) {
  const customerCurrency = String(row.customer_currency || row.currency || "").toUpperCase();
  const providerCurrency = String(row.provider_currency || row.currency || "").toUpperCase();
  const customerTotalMinor = Number(row.customer_total_minor ?? row.charge_total_minor ?? 0);
  const providerTotalMinor = Number(row.provider_total_minor ?? row.duffel_total_minor ?? 0);
  const estimatedProcessingMinor = row.customer_estimated_processing_minor == null
    ? null
    : Number(row.customer_estimated_processing_minor);
  const estimatedProfitMinor = row.customer_estimated_gross_margin_minor == null
    ? null
    : Number(row.customer_estimated_gross_margin_minor);
  const actualProcessingMinor = row.stripe_actual_processing_minor == null
    ? null
    : Number(row.stripe_actual_processing_minor);
  return {
    id: row.id,
    route: itinerarySummary(row.offer_snapshot),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    status: row.booking_status,
    customer: { currency: customerCurrency, totalMinor: customerTotalMinor },
    provider: { currency: providerCurrency, totalMinor: providerTotalMinor },
    estimatedProcessingMinor,
    actualProcessingMinor,
    actualProcessingCurrency: row.stripe_actual_processing_currency || null,
    estimatedProfitMinor,
    profitPercent: estimatedProfitMinor == null || customerTotalMinor <= 0
      ? null
      : Number(((estimatedProfitMinor / customerTotalMinor) * 100).toFixed(2)),
    bookingReference: row.duffel_booking_reference || null,
    pricingConfig: {
      source: row.pricing_config_source || "legacy_session",
      version: row.pricing_config_version == null ? null : Number(row.pricing_config_version),
    },
  };
}

function pricingConfigChanges(current, candidate) {
  const changes = [];
  for (const field of Object.keys(FLIGHT_CONFIG_FIELDS)) {
    if (current[field] !== candidate[field]) changes.push({ field, from: current[field], to: candidate[field] });
  }
  for (const currency of Object.keys(current.roundingRules || {})) {
    if (current.roundingRules[currency] !== candidate.roundingRules?.[currency]) {
      changes.push({
        field: `roundingRules.${currency}`,
        from: current.roundingRules[currency],
        to: candidate.roundingRules?.[currency],
      });
    }
  }
  return changes;
}

function currencySettingsChanges(current, candidate) {
  const changes = [];
  for (const code of SUPPORTED_CUSTOMER_CURRENCIES) {
    if (current.currencies?.[code]?.enabled !== candidate.currencies?.[code]?.enabled) {
      changes.push({
        field: `currencies.${code}.enabled`,
        from: current.currencies?.[code]?.enabled,
        to: candidate.currencies?.[code]?.enabled,
      });
    }
    if (current.currencies?.[code]?.roundingIncrementMinor !== candidate.currencies?.[code]?.roundingIncrementMinor) {
      changes.push({
        field: `currencies.${code}.roundingIncrementMinor`,
        from: current.currencies?.[code]?.roundingIncrementMinor,
        to: candidate.currencies?.[code]?.roundingIncrementMinor,
      });
    }
  }
  for (const region of Object.keys(DEFAULT_CURRENCY_REGION_DEFAULTS)) {
    if (current.defaultsByRegion?.[region] !== candidate.defaultsByRegion?.[region]) {
      changes.push({
        field: `defaultsByRegion.${region}`,
        from: current.defaultsByRegion?.[region],
        to: candidate.defaultsByRegion?.[region],
      });
    }
  }
  return changes;
}

async function nextPricingVersion(client, product, environment) {
  const result = await client.query(
    "select coalesce(max(version), 0) + 1 as version from pricing_configurations where product = $1 and environment = $2",
    [product, environment]
  );
  return Number(result.rows[0]?.version || 1);
}

async function saveVersionedConfigDraft(dbPool, options) {
  const { product, environment, config, actor } = options;
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    await client.query("select pg_advisory_xact_lock(hashtext($1))", [`pricing:${product}:${environment}`]);
    const version = await nextPricingVersion(client, product, environment);
    await client.query(
      `update pricing_configurations set status = 'archived', archived_at = now()
        where product = $1 and environment = $2 and status = 'draft'`,
      [product, environment]
    );
    const result = await client.query(
      `insert into pricing_configurations (product, environment, version, status, config, created_by)
       values ($1, $2, $3, 'draft', $4::jsonb, $5)
       returning version, status, config, created_by, created_at`,
      [product, environment, version, JSON.stringify(config), actor]
    );
    await client.query("commit");
    return result.rows[0];
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function activateVersionedConfigDraft(dbPool, options) {
  const { product, environment, draftVersion, actor, normalizeConfig } = options;
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    await client.query("select pg_advisory_xact_lock(hashtext($1))", [`pricing:${product}:${environment}`]);
    const draftResult = await client.query(
      `select version, config from pricing_configurations
        where product = $1 and environment = $2 and version = $3 and status = 'draft'
        for update`,
      [product, environment, draftVersion]
    );
    const draft = draftResult.rows[0];
    if (!draft) {
      const error = new Error("The selected draft is no longer available.");
      error.code = "draft_not_found";
      throw error;
    }
    const config = normalizeConfig(draft.config);
    const version = await nextPricingVersion(client, product, environment);
    await client.query(
      `update pricing_configurations set status = 'archived', archived_at = now()
        where product = $1 and environment = $2 and status = 'active'`,
      [product, environment]
    );
    await client.query(
      `update pricing_configurations set status = 'archived', archived_at = now()
        where product = $1 and environment = $2 and version = $3 and status = 'draft'`,
      [product, environment, draftVersion]
    );
    const activeResult = await client.query(
      `insert into pricing_configurations (
         product, environment, version, status, config, created_by,
         activated_by, activated_at, based_on_version
       ) values ($1, $2, $3, 'active', $4::jsonb, $5, $5, now(), $6)
       returning version, status, config, created_by, activated_by, activated_at, based_on_version`,
      [product, environment, version, JSON.stringify(config), actor, draftVersion]
    );
    await client.query("commit");
    return activeResult.rows[0];
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function rollbackVersionedConfigVersion(dbPool, options) {
  const { product, environment, targetVersion, actor, normalizeConfig } = options;
  const client = await dbPool.connect();
  try {
    await client.query("begin");
    await client.query("select pg_advisory_xact_lock(hashtext($1))", [`pricing:${product}:${environment}`]);
    const targetResult = await client.query(
      `select version, config from pricing_configurations
        where product = $1 and environment = $2 and version = $3
        for share`,
      [product, environment, targetVersion]
    );
    const target = targetResult.rows[0];
    if (!target) {
      const error = new Error("The selected pricing version does not exist.");
      error.code = "pricing_version_not_found";
      throw error;
    }
    const config = normalizeConfig(target.config);
    const version = await nextPricingVersion(client, product, environment);
    await client.query(
      `update pricing_configurations set status = 'archived', archived_at = now()
        where product = $1 and environment = $2 and status = 'active'`,
      [product, environment]
    );
    const activeResult = await client.query(
      `insert into pricing_configurations (
         product, environment, version, status, config, created_by,
         activated_by, activated_at, based_on_version
       ) values ($1, $2, $3, 'active', $4::jsonb, $5, $5, now(), $6)
       returning version, status, config, created_by, activated_by, activated_at, based_on_version`,
      [product, environment, version, JSON.stringify(config), actor, targetVersion]
    );
    await client.query("commit");
    return activeResult.rows[0];
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function saveFlightPricingDraft(dbPool, options) {
  return saveVersionedConfigDraft(dbPool, { ...options, product: "flights" });
}

async function saveCurrencySettingsDraft(dbPool, options) {
  return saveVersionedConfigDraft(dbPool, { ...options, product: "currencies" });
}

async function activateFlightPricingDraft(dbPool, options) {
  return activateVersionedConfigDraft(dbPool, {
    ...options,
    product: "flights",
    normalizeConfig: normalizeFlightPricingConfig,
  });
}

async function activateCurrencySettingsDraft(dbPool, options) {
  return activateVersionedConfigDraft(dbPool, {
    ...options,
    product: "currencies",
    normalizeConfig: normalizeCurrencySettingsConfig,
  });
}

async function rollbackFlightPricingVersion(dbPool, options) {
  return rollbackVersionedConfigVersion(dbPool, {
    ...options,
    product: "flights",
    normalizeConfig: normalizeFlightPricingConfig,
  });
}

async function rollbackCurrencySettingsVersion(dbPool, options) {
  return rollbackVersionedConfigVersion(dbPool, {
    ...options,
    product: "currencies",
    normalizeConfig: normalizeCurrencySettingsConfig,
  });
}

function loginHtml() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive"><title>Zippi Admin · Sign in</title>
<link rel="stylesheet" href="/admin/assets/admin.css"></head>
<body class="login-page"><main class="login-card"><img class="login-logo" src="/admin/assets/zippi-logo-nano.png" alt="Zippi"><p class="eyebrow">Private workspace</p>
<h1>Zippi Admin</h1><p class="login-copy">Simple pricing and booking controls for the Zippi business team.</p>
<form method="post" action="/admin/session"><label for="secret">Admin access key</label>
<input id="secret" name="secret" type="password" required autocomplete="current-password" autofocus>
<button type="submit">Continue</button></form><p class="login-note">Access is restricted and activity is not indexed.</p></main></body></html>`;
}

function createAdminDashboardRouter(options = {}) {
  const {
    dbPool,
    adminSecret = "",
    sessionSecret = "",
    adminActor = "admin",
    pricingConfigResolver,
    currencySettingsResolver,
    getExchangeRates,
  } = options;
  const pricingEnvironment = pricingConfigResolver?.environment || "test";
  const router = express.Router();
  const publicDirectory = path.join(__dirname, "..", "admin", "public");
  const loginAttempts = new Map();

  router.use((req, res, next) => {
    res.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    res.set("Cache-Control", "no-store");
    next();
  });
  router.get("/assets/admin.css", (_req, res) => res.sendFile(path.join(publicDirectory, "admin.css")));
  router.get("/assets/zippi-logo-nano.png", (_req, res) => res.sendFile(path.join(publicDirectory, "zippi-logo-nano.png")));
  router.get("/login", (req, res) => {
    if (verifyAdminSessionToken(cookieValue(req, ADMIN_COOKIE), sessionSecret)) return res.redirect("/admin/");
    return res.type("html").send(loginHtml());
  });
  router.post("/session", (req, res) => {
    if (!adminSecret || !sessionSecret) return res.status(503).type("html").send("Zippi Admin authentication is not configured.");
    const key = String(req.ip || req.socket?.remoteAddress || "unknown");
    const now = Date.now();
    const recent = (loginAttempts.get(key) || []).filter((timestamp) => now - timestamp < 10 * 60 * 1000);
    recent.push(now);
    loginAttempts.set(key, recent);
    if (recent.length > 10) return res.status(429).type("html").send("Too many sign-in attempts. Try again later.");
    if (!constantTimeEqual(req.body?.secret, adminSecret)) return res.status(401).type("html").send(loginHtml());
    loginAttempts.delete(key);
    res.cookie(ADMIN_COOKIE, createAdminSessionToken(sessionSecret, now, adminActor), {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: SESSION_TTL_MS,
      path: "/admin",
    });
    return res.redirect(303, "/admin/");
  });

  router.use((req, res, next) => {
    const session = verifyAdminSessionToken(cookieValue(req, ADMIN_COOKIE), sessionSecret);
    if (session) {
      req.zippiAdmin = session;
      return next();
    }
    if (req.path.startsWith("/api/")) return res.status(401).json({ ok: false, error: "admin_auth_required" });
    return res.redirect("/admin/login");
  });
  router.get("/assets/admin.js", (_req, res) => res.sendFile(path.join(publicDirectory, "admin.js")));
  router.post("/logout", (_req, res) => {
    res.clearCookie(ADMIN_COOKIE, { path: "/admin", secure: true, sameSite: "strict" });
    return res.redirect(303, "/admin/login");
  });

  router.get("/api/config", async (_req, res) => {
    const [resolved, resolvedCurrencies, exchangeRates] = await Promise.all([
      pricingConfigResolver.resolve(),
      currencySettingsResolver?.resolve?.() || Promise.resolve(null),
      getExchangeRates?.() || Promise.resolve(null),
    ]);
    let latestDraft = null;
    let history = [];
    let currencyDraft = null;
    let currencyHistory = [];
    if (dbPool) {
      try {
        const [draftResult, historyResult, currencyDraftResult, currencyHistoryResult] = await Promise.all([
          dbPool.query(
            `select version, config, created_by, created_at
             from pricing_configurations
            where product = 'flights' and environment = $1 and status = 'draft'
            order by version desc limit 1`,
            [pricingEnvironment]
          ),
          dbPool.query(
            `select version, status, created_by, created_at, activated_by, activated_at,
                    archived_at, based_on_version
               from pricing_configurations
              where product = 'flights' and environment = $1
              order by version desc limit 20`,
            [pricingEnvironment]
          ),
          dbPool.query(
            `select version, config, created_by, created_at
             from pricing_configurations
            where product = 'currencies' and environment = $1 and status = 'draft'
            order by version desc limit 1`,
            [pricingEnvironment]
          ),
          dbPool.query(
            `select version, status, created_by, created_at, activated_by, activated_at,
                    archived_at, based_on_version
               from pricing_configurations
              where product = 'currencies' and environment = $1
              order by version desc limit 20`,
            [pricingEnvironment]
          ),
        ]);
        latestDraft = draftResult.rows[0] || null;
        history = historyResult.rows;
        currencyDraft = currencyDraftResult.rows[0] || null;
        currencyHistory = currencyHistoryResult.rows;
      } catch (error) {
        if (error.code !== "42P01") throw error;
      }
    }
    return res.json({
      ok: true,
      flights: {
        source: resolved.source,
        version: resolved.version,
        environment: resolved.environment,
        activatedAt: resolved.activatedAt,
        values: resolved.config,
        fallbackValues: pricingConfigResolver.fallbackConfig,
        rounding: resolved.config.roundingRules,
        liveWriteEnabled: Boolean(dbPool),
        latestDraft,
        history,
      },
      currencies: resolvedCurrencies ? {
        source: resolvedCurrencies.source,
        version: resolvedCurrencies.version,
        environment: resolvedCurrencies.environment,
        activatedAt: resolvedCurrencies.activatedAt,
        values: resolvedCurrencies.config,
        fallbackValues: currencySettingsResolver?.fallbackConfig || null,
        liveWriteEnabled: Boolean(dbPool),
        latestDraft: currencyDraft,
        history: currencyHistory,
        fx: exchangeRates ? {
          source: exchangeRates.source || null,
          updatedAt: exchangeRates.updatedAt || null,
          stale: Boolean(exchangeRates.stale),
          representativeRates: SUPPORTED_CUSTOMER_CURRENCIES.reduce((acc, code) => {
            acc[code] = code === "USD" ? 1 : (exchangeRates.rates?.[code] ?? null);
            return acc;
          }, {}),
        } : null,
      } : null,
      hotels: {
        status: "unsupported",
        source: "provider_display_only",
        findings: [
          "Shared backend hotel search and room pricing exist.",
          "No authoritative hotel sell-price, payment, booking-session, or profit model exists yet.",
          "Legacy iOS cards round displayed nightly prices up to the nearest 5, but this is not a booking price contract.",
        ],
      },
    });
  });

  router.post("/api/flights/preview", async (req, res) => {
    try {
      const [resolved, resolvedCurrencies] = await Promise.all([
        pricingConfigResolver.resolve(),
        currencySettingsResolver?.resolve?.() || Promise.resolve(null),
      ]);
      const exchangeRates = await getExchangeRates?.();
      const previewConfig = resolvedCurrencies
        ? {
            ...resolved.config,
            roundingRules: Object.fromEntries(
              Object.entries(resolvedCurrencies.config.currencies).map(([code, value]) => [code, value.roundingIncrementMinor])
            ),
          }
        : resolved.config;
      return res.json(buildFlightPricingPreview(req.body, previewConfig, exchangeRates));
    } catch (error) {
      return res.status(error.code === "exchange_rate_unavailable" ? 503 : 400).json({
        ok: false,
        error: error.code || "invalid_preview",
        field: error.field || null,
        message: error.message,
      });
    }
  });

  router.post("/api/flights/config/drafts", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    if (req.body?.confirmed !== true) return res.status(400).json({ ok: false, error: "confirmation_required" });
    let config;
    try {
      const resolved = await pricingConfigResolver.resolve();
      config = sanitizeFlightPricingConfig(req.body?.config, resolved.config);
    } catch (error) {
      return res.status(400).json({ ok: false, error: error.code, field: error.field });
    }
    try {
      const draft = await saveFlightPricingDraft(dbPool, {
        environment: pricingEnvironment,
        config,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.status(201).json({ ok: true, draft, activePricingChanged: false });
    } catch (error) {
      if (error.code === "42P01") return res.status(503).json({ ok: false, error: "pricing_config_storage_not_migrated" });
      throw error;
    }
  });

  async function loadPricingVersion(version, requiredStatus = null) {
    return loadConfigVersion("flights", version, requiredStatus);
  }

  async function loadConfigVersion(product, version, requiredStatus = null) {
    const params = [product, pricingEnvironment, version];
    const statusClause = requiredStatus ? " and status = $4" : "";
    if (requiredStatus) params.push(requiredStatus);
    const result = await dbPool.query(
      `select version, status, config from pricing_configurations
        where product = $1 and environment = $2 and version = $3${statusClause}`,
      params
    );
    return result.rows[0] || null;
  }

  async function reviewPricingVersion(req, res, requiredStatus = null) {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const version = Number(req.params.version);
    if (!Number.isSafeInteger(version) || version <= 0) return res.status(400).json({ ok: false, error: "invalid_pricing_version" });
    const candidateRow = await loadPricingVersion(version, requiredStatus);
    if (!candidateRow) return res.status(404).json({ ok: false, error: requiredStatus === "draft" ? "draft_not_found" : "pricing_version_not_found" });
    try {
      const [resolved, resolvedCurrencies] = await Promise.all([
        pricingConfigResolver.resolve(),
        currencySettingsResolver?.resolve?.() || Promise.resolve(null),
      ]);
      const candidate = normalizeFlightPricingConfig(candidateRow.config);
      const exchangeRates = await getExchangeRates?.();
      const currentConfig = resolvedCurrencies
        ? {
            ...resolved.config,
            roundingRules: Object.fromEntries(
              Object.entries(resolvedCurrencies.config.currencies).map(([code, value]) => [code, value.roundingIncrementMinor])
            ),
          }
        : resolved.config;
      const candidateConfig = resolvedCurrencies
        ? {
            ...candidate,
            roundingRules: Object.fromEntries(
              Object.entries(resolvedCurrencies.config.currencies).map(([code, value]) => [code, value.roundingIncrementMinor])
            ),
          }
        : candidate;
      const sample = {
        providerAmount: req.body?.providerAmount ?? 200,
        providerCurrency: req.body?.providerCurrency || "USD",
        customerCurrency: req.body?.customerCurrency || "CAD",
      };
      return res.json({
        ok: true,
        version,
        status: candidateRow.status,
        changes: pricingConfigChanges(resolved.config, candidate),
        current: buildFlightPricingPreview({ ...sample, config: currentConfig }, currentConfig, exchangeRates),
        candidate: buildFlightPricingPreview({ ...sample, config: candidateConfig }, candidateConfig, exchangeRates),
      });
    } catch (error) {
      return res.status(error.code === "exchange_rate_unavailable" ? 503 : 400).json({
        ok: false,
        error: error.code || "invalid_pricing_version",
        message: error.message,
      });
    }
  }

  router.post("/api/flights/config/drafts/:version/review", (req, res) => reviewPricingVersion(req, res, "draft"));
  router.post("/api/flights/config/versions/:version/review", (req, res) => reviewPricingVersion(req, res));

  router.post("/api/flights/config/drafts/:version/activate", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const draftVersion = Number(req.params.version);
    if (req.body?.confirmed !== true || Number(req.body?.reviewedVersion) !== draftVersion) {
      return res.status(400).json({ ok: false, error: "activation_confirmation_required" });
    }
    try {
      const active = await activateFlightPricingDraft(dbPool, {
        environment: pricingEnvironment,
        draftVersion,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.json({ ok: true, active });
    } catch (error) {
      const status = error.code === "draft_not_found" ? 409 : 400;
      return res.status(status).json({ ok: false, error: error.code || "activation_failed", message: error.message });
    }
  });

  router.post("/api/flights/config/versions/:version/rollback", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const targetVersion = Number(req.params.version);
    if (req.body?.confirmed !== true || Number(req.body?.reviewedVersion) !== targetVersion) {
      return res.status(400).json({ ok: false, error: "rollback_confirmation_required" });
    }
    try {
      const active = await rollbackFlightPricingVersion(dbPool, {
        environment: pricingEnvironment,
        targetVersion,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.json({ ok: true, active });
    } catch (error) {
      const status = error.code === "pricing_version_not_found" ? 404 : 400;
      return res.status(status).json({ ok: false, error: error.code || "rollback_failed", message: error.message });
    }
  });

  router.post("/api/currencies/config/drafts", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    if (req.body?.confirmed !== true) return res.status(400).json({ ok: false, error: "confirmation_required" });
    let config;
    try {
      const resolved = await currencySettingsResolver.resolve();
      config = sanitizeCurrencySettingsConfig(req.body?.config, resolved.config);
    } catch (error) {
      return res.status(400).json({ ok: false, error: error.code, field: error.field });
    }
    try {
      const draft = await saveCurrencySettingsDraft(dbPool, {
        environment: pricingEnvironment,
        config,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.status(201).json({ ok: true, draft });
    } catch (error) {
      if (error.code === "42P01") return res.status(503).json({ ok: false, error: "pricing_config_storage_not_migrated" });
      throw error;
    }
  });

  router.post("/api/currencies/config/drafts/:version/review", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const version = Number(req.params.version);
    if (!Number.isSafeInteger(version) || version <= 0) return res.status(400).json({ ok: false, error: "invalid_pricing_version" });
    const candidateRow = await loadConfigVersion("currencies", version, "draft");
    if (!candidateRow) return res.status(404).json({ ok: false, error: "draft_not_found" });
    const resolved = await currencySettingsResolver.resolve();
    const candidate = normalizeCurrencySettingsConfig(candidateRow.config, resolved.config);
    return res.json({
      ok: true,
      version,
      status: candidateRow.status,
      changes: currencySettingsChanges(resolved.config, candidate),
      current: resolved.config,
      candidate,
    });
  });
  router.post("/api/currencies/config/versions/:version/review", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const version = Number(req.params.version);
    if (!Number.isSafeInteger(version) || version <= 0) return res.status(400).json({ ok: false, error: "invalid_pricing_version" });
    const candidateRow = await loadConfigVersion("currencies", version);
    if (!candidateRow) return res.status(404).json({ ok: false, error: "pricing_version_not_found" });
    const resolved = await currencySettingsResolver.resolve();
    const candidate = normalizeCurrencySettingsConfig(candidateRow.config, resolved.config);
    return res.json({
      ok: true,
      version,
      status: candidateRow.status,
      changes: currencySettingsChanges(resolved.config, candidate),
      current: resolved.config,
      candidate,
    });
  });

  router.post("/api/currencies/config/drafts/:version/activate", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const draftVersion = Number(req.params.version);
    if (req.body?.confirmed !== true || Number(req.body?.reviewedVersion) !== draftVersion) {
      return res.status(400).json({ ok: false, error: "activation_confirmation_required" });
    }
    try {
      const active = await activateCurrencySettingsDraft(dbPool, {
        environment: pricingEnvironment,
        draftVersion,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.json({ ok: true, active });
    } catch (error) {
      const status = error.code === "draft_not_found" ? 409 : 400;
      return res.status(status).json({ ok: false, error: error.code || "activation_failed", message: error.message });
    }
  });

  router.post("/api/currencies/config/versions/:version/rollback", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const targetVersion = Number(req.params.version);
    if (req.body?.confirmed !== true || Number(req.body?.reviewedVersion) !== targetVersion) {
      return res.status(400).json({ ok: false, error: "rollback_confirmation_required" });
    }
    try {
      const active = await rollbackCurrencySettingsVersion(dbPool, {
        environment: pricingEnvironment,
        targetVersion,
        actor: req.zippiAdmin.actor || adminActor,
      });
      return res.json({ ok: true, active });
    } catch (error) {
      const status = error.code === "pricing_version_not_found" ? 404 : 400;
      return res.status(status).json({ ok: false, error: error.code || "rollback_failed", message: error.message });
    }
  });

  router.get("/api/overview", async (_req, res) => {
    if (!dbPool) return res.json({ ok: true, available: false, reason: "database_not_configured" });
    const [statusResult, customerResult, providerResult] = await Promise.all([
      dbPool.query(`select booking_status as status, count(*)::int as count
                      from flight_booking_sessions group by booking_status order by booking_status`),
      dbPool.query(`select coalesce(customer_currency, currency) as currency,
                           count(*) filter (where stripe_payment_status = 'succeeded'
                             and booking_status <> 'booking_failed_refunded')::int as bookings,
                           coalesce(sum(coalesce(customer_total_minor, charge_total_minor)) filter (
                             where stripe_payment_status = 'succeeded'
                               and booking_status <> 'booking_failed_refunded'), 0)::bigint as revenue_minor,
                           coalesce(sum(customer_estimated_processing_minor) filter (
                             where stripe_payment_status = 'succeeded'
                               and booking_status <> 'booking_failed_refunded'), 0)::bigint as processing_minor,
                           coalesce(sum(customer_estimated_gross_margin_minor) filter (
                             where stripe_payment_status = 'succeeded'
                               and booking_status <> 'booking_failed_refunded'), 0)::bigint as profit_minor
                      from flight_booking_sessions
                     group by coalesce(customer_currency, currency)
                     order by currency`),
      dbPool.query(`select coalesce(provider_currency, currency) as currency,
                           coalesce(sum(coalesce(provider_total_minor, duffel_total_minor)), 0)::bigint as cost_minor
                      from flight_booking_sessions
                     where booking_status = 'confirmed'
                     group by coalesce(provider_currency, currency)
                     order by currency`),
    ]);
    const totalBookings = statusResult.rows.reduce((sum, row) => sum + Number(row.count), 0);
    return res.json({
      ok: true,
      available: true,
      totals: { totalBookings, flightBookings: totalBookings, hotelBookings: 0 },
      statuses: statusResult.rows,
      customerEconomics: customerResult.rows,
      providerCosts: providerResult.rows,
      hotelsAvailable: false,
    });
  });

  router.get("/api/flights/bookings", async (req, res) => {
    if (!dbPool) return res.json({ ok: true, available: false, bookings: [] });
    const requestedLimit = Number(req.query.limit || 50);
    const limit = Number.isSafeInteger(requestedLimit) ? Math.min(100, Math.max(1, requestedLimit)) : 50;
    const result = await dbPool.query(
      `select id, offer_snapshot, currency, charge_total_minor, duffel_total_minor,
              customer_currency, customer_total_minor, provider_currency, provider_total_minor,
              customer_estimated_processing_minor, customer_estimated_gross_margin_minor,
              stripe_actual_processing_minor, stripe_actual_processing_currency,
              pricing_config_source, pricing_config_version,
              booking_status, duffel_booking_reference, created_at, updated_at
         from flight_booking_sessions order by created_at desc limit $1`,
      [limit]
    );
    return res.json({ ok: true, available: true, bookings: result.rows.map(bookingSummary) });
  });

  router.get("/api/flights/attention", async (_req, res) => {
    if (!dbPool) return res.json({ ok: true, available: false, bookings: [] });
    const result = await dbPool.query(
      `select id, user_id, offer_snapshot, currency, charge_total_minor, duffel_total_minor,
              customer_currency, customer_total_minor, provider_currency, provider_total_minor,
              customer_estimated_processing_minor, customer_estimated_gross_margin_minor,
              stripe_actual_processing_minor, stripe_actual_processing_currency,
              booking_mode, booking_status, stripe_payment_status, recovery_status,
              stripe_payment_intent_id, stripe_refund_id, duffel_offer_id, duffel_order_id,
              duffel_booking_reference, failure_code, failure_message, created_at, updated_at
         from flight_booking_sessions
        where booking_status in ('booking_unknown', 'booking_failed_refund_pending')
           or recovery_status = 'refund_failed'
           or (stripe_payment_status = 'succeeded'
               and duffel_order_id is null
               and booking_status not in ('booking_failed_refunded', 'confirmed'))
        order by updated_at asc limit 100`
    );
    return res.json({
      ok: true,
      available: true,
      bookings: result.rows.map((row) => ({
        ...bookingSummary(row),
        userId: row.user_id,
        bookingMode: row.booking_mode || "test",
        paymentStatus: row.stripe_payment_status,
        recoveryStatus: row.recovery_status,
        stripePaymentIntentId: row.stripe_payment_intent_id,
        stripeRefundId: row.stripe_refund_id,
        duffelOfferId: row.duffel_offer_id,
        duffelOrderId: row.duffel_order_id,
        failure: row.failure_code ? { code: row.failure_code, message: row.failure_message } : null,
      })),
    });
  });

  router.get("/api/flights/bookings/:id", async (req, res) => {
    if (!dbPool) return res.status(503).json({ ok: false, error: "database_not_configured" });
    const result = await dbPool.query(
      `select id, offer_snapshot, currency, charge_total_minor, duffel_total_minor,
              customer_currency, customer_total_minor, provider_currency, provider_offer_minor,
              provider_services_minor, provider_total_minor, customer_fx_rate, customer_fx_source,
              customer_fx_margin_bps, customer_raw_converted_minor, customer_fx_protection_minor,
              customer_converted_minor, customer_zippi_markup_bps, customer_zippi_markup_minor,
              customer_zippi_fee_minor, customer_payment_processing_percent_bps,
              customer_payment_processing_fixed_minor, customer_payment_processing_cross_border_bps,
              customer_payment_processing_allowance_minor, customer_estimated_processing_minor,
              customer_min_margin_target_minor, customer_min_margin_top_up_minor,
              customer_pre_round_minor, customer_rounding_increment_minor,
              customer_rounding_adjustment_minor, customer_estimated_gross_margin_minor,
              booking_mode, user_id, traveler_info, contact_info, payload_snapshot,
              selected_services, confirmation_snapshot, stripe_payment_intent_id,
              stripe_charge_id, stripe_balance_transaction_id, stripe_actual_processing_minor,
              stripe_actual_processing_currency, stripe_fee_reconciled_at, stripe_refund_id,
              duffel_offer_id, duffel_order_id, recovery_status, failure_message,
              pricing_config_source, pricing_config_version,
              booking_status, stripe_payment_status, duffel_booking_reference,
              failure_code, created_at, updated_at, confirmed_at
         from flight_booking_sessions where id = $1`,
      [req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: "booking_not_found" });
    const row = result.rows[0];
    const {
      offer_snapshot: _offerSnapshot,
      traveler_info: _travelerInfo,
      contact_info: _contactInfo,
      payload_snapshot: _payloadSnapshot,
      selected_services: _selectedServices,
      confirmation_snapshot: _confirmationSnapshot,
      ...economics
    } = row;
    const travelers = Array.isArray(row.traveler_info) ? row.traveler_info.map((traveler) => ({
      type: traveler.travelerType || traveler.traveler_type || traveler.type || null,
      title: traveler.title || null,
      firstName: traveler.firstName || traveler.given_name || null,
      middleName: traveler.middleName || null,
      lastName: traveler.lastName || traveler.family_name || null,
      dateOfBirth: traveler.dateOfBirthISO || traveler.born_on || null,
      nationality: traveler.nationality || null,
      passportCountry: traveler.passportCountry || traveler.passport_country || null,
      passportLastFour: String(traveler.passportNumber || traveler.passport_number || "").slice(-4) || null,
    })) : [];
    return res.json({
      ok: true,
      booking: {
        ...bookingSummary(row),
        economics,
        support: {
          userId: row.user_id,
          bookingMode: row.booking_mode || "test",
          stripePaymentIntentId: row.stripe_payment_intent_id,
          stripeChargeId: row.stripe_charge_id,
          stripeBalanceTransactionId: row.stripe_balance_transaction_id,
          stripeRefundId: row.stripe_refund_id,
          duffelOfferId: row.duffel_offer_id,
          duffelOrderId: row.duffel_order_id,
          recoveryStatus: row.recovery_status,
          contact: row.contact_info || {},
          travelers,
          itinerary: row.offer_snapshot?.slices || [],
          selectedServices: row.selected_services || [],
          manageBooking: "not_implemented",
        },
      },
    });
  });

  router.get(["/", "/overview", "/flights", "/currencies", "/flights/bookings", "/hotels", "/hotels/bookings"], (_req, res) => {
    return res.sendFile(path.join(publicDirectory, "index.html"));
  });
  return router;
}

module.exports = {
  ADMIN_COOKIE,
  activateCurrencySettingsDraft,
  activateFlightPricingDraft,
  bookingSummary,
  buildFlightPricingPreview,
  createAdminDashboardRouter,
  createAdminSessionToken,
  currencySettingsChanges,
  pricingConfigChanges,
  rollbackCurrencySettingsVersion,
  rollbackFlightPricingVersion,
  sanitizeCurrencySettingsConfig,
  sanitizeFlightPricingConfig,
  saveCurrencySettingsDraft,
  saveFlightPricingDraft,
  verifyAdminSessionToken,
};
