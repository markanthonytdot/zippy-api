const supportedCurrencyCodes = ["CAD", "USD", "EUR", "COP"];
const currencyRegions = ["CA", "US", "EU", "CO", "DEFAULT"];

const state = {
  config: null,
  draft: null,
  history: [],
  currencyConfig: null,
  currencyDraft: null,
  currencyHistory: [],
  currencyFx: null,
  currencySource: null,
  currencyVersion: null,
  route: null,
  previewTimer: null,
};

const pages = {
  overview: {
    title: "Overview",
    path: "/admin/overview",
    subtitle: "Simple controls for pricing, bookings, and profit visibility.",
  },
  flights: {
    title: "Flight pricing",
    path: "/admin/flights",
    subtitle: "Adjust the customer price model without changing live checkout until you activate a reviewed draft.",
  },
  currencies: {
    title: "Currency settings",
    path: "/admin/currencies",
    subtitle: "Control enabled checkout currencies, defaults, and round-up behavior from one shared backend contract.",
  },
  "flight-bookings": {
    title: "Flight bookings",
    path: "/admin/flights/bookings",
    subtitle: "See what customers paid, what suppliers cost, and what each booking kept for Zippi.",
  },
  hotels: {
    title: "Hotels",
    path: "/admin/hotels",
    subtitle: "Visible for planning, but not connected to commerce or checkout yet.",
  },
  "hotel-bookings": {
    title: "Hotel bookings",
    path: "/admin/hotels/bookings",
    subtitle: "This stays empty until hotel commerce is connected to a real booking ledger.",
  },
};

function routeFromPath(pathname) {
  if (pathname.includes("/flights/bookings")) return "flight-bookings";
  if (pathname.includes("/hotels/bookings")) return "hotel-bookings";
  if (pathname.endsWith("/currencies")) return "currencies";
  if (pathname.endsWith("/flights")) return "flights";
  if (pathname.endsWith("/hotels")) return "hotels";
  return "overview";
}

async function api(path, options = {}) {
  const response = await fetch(`/admin/api${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (response.status === 401) {
    window.location.assign("/admin/login");
    throw new Error("Sign in required");
  }
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.message || payload.error || "Request failed");
  return payload;
}

function navigate(route, push = true) {
  state.route = route;
  document.querySelectorAll("[data-page]").forEach((element) => {
    element.hidden = element.dataset.page !== route;
  });
  document.querySelectorAll("nav a[data-route]").forEach((element) => {
    element.classList.toggle("active", element.dataset.route === route);
  });
  document.getElementById("page-title").textContent = pages[route].title;
  document.getElementById("page-subtitle").textContent = pages[route].subtitle;
  if (push) history.pushState({ route }, "", pages[route].path);
  if (route === "overview") loadOverview();
  if (route === "currencies") loadCurrencies();
  if (route === "flight-bookings") loadFlightBookings();
}

function minorFactor(currency) {
  return ["JPY", "KRW", "VND"].includes(String(currency).toUpperCase()) ? 1 : 100;
}

function money(minor, currency) {
  if (minor == null || !currency) return "Not available";
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(Number(minor) / minorFactor(currency));
}

function integer(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function escapeHtml(value) {
  const node = document.createElement("span");
  node.textContent = String(value ?? "");
  return node.innerHTML;
}

function toast(message) {
  const element = document.getElementById("toast");
  element.textContent = message;
  element.classList.add("visible");
  setTimeout(() => element.classList.remove("visible"), 3200);
}

function empty(title, copy) {
  return `<div class="empty-state"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(copy)}</p></div>`;
}

function summaryCard({ title, copy, lines, accent = false }) {
  return `<article class="summary-card${accent ? " accent" : ""}">
    <p class="summary-label">Business summary</p>
    <h3>${escapeHtml(title)}</h3>
    <p class="summary-copy">${escapeHtml(copy)}</p>
    ${lines ? `<div class="summary-lines">${lines}</div>` : `<div class="summary-empty">Waiting for booking data.</div>`}
  </article>`;
}

function renderSummaryLines(items, formatter) {
  if (!items.length) return "";
  return items.map((item) => `
    <div class="summary-line">
      <span>${escapeHtml(item.label)}</span>
      <strong>${escapeHtml(formatter(item))}</strong>
    </div>
  `).join("");
}

function averageProfitItems(customerEconomics) {
  return customerEconomics
    .filter((item) => Number(item.bookings) > 0)
    .map((item) => ({
      label: item.currency,
      currency: item.currency,
      valueMinor: Math.round(Number(item.profit_minor || 0) / Number(item.bookings)),
    }));
}

function loadOverviewEmptyState() {
  document.getElementById("overview-summary").innerHTML = [
    summaryCard({
      title: "Revenue",
      copy: "Customer charge totals will appear here after the first booking.",
      lines: "",
      accent: true,
    }),
    summaryCard({
      title: "Provider cost",
      copy: "Supplier costs stay grouped in their original payout currency.",
      lines: "",
    }),
    summaryCard({
      title: "Payment costs",
      copy: "Estimated card-processing costs appear after a paid booking.",
      lines: "",
    }),
    summaryCard({
      title: "Gross profit",
      copy: "Profit remains separate from supplier cost and payment costs.",
      lines: "",
      accent: true,
    }),
    summaryCard({
      title: "Average profit per booking",
      copy: "Average profit updates once bookings have completed.",
      lines: "",
    }),
  ].join("");
  document.getElementById("overview-operations").innerHTML = renderOperations([
    { label: "Booking sessions", value: 0, note: "No flight bookings yet" },
    { label: "Confirmed bookings", value: 0, note: "No completed flight orders yet" },
    { label: "Flight ledger", value: 0, note: "Bookings will appear here automatically" },
    { label: "Hotel commerce", value: "Not connected", note: "Hotels remain visible but not bookable" },
  ]);
  document.getElementById("overview-statuses").innerHTML = empty(
    "No booking statuses yet",
    "Status mix will appear once booking sessions start moving through checkout."
  );
}

function renderOperations(items) {
  return `<div class="operations-grid">${items.map((item) => `
    <div class="operation-card">
      <span>${escapeHtml(item.label)}</span>
      <strong>${escapeHtml(typeof item.value === "number" ? integer(item.value) : item.value)}</strong>
      <small>${escapeHtml(item.note)}</small>
    </div>
  `).join("")}</div>`;
}

function renderStatuses(statuses) {
  if (!statuses.length) {
    return empty("No booking statuses yet", "Status mix will appear after bookings begin.");
  }
  return `<div class="status-list">${statuses.map((item) => `
    <div class="status-row">
      <strong>${escapeHtml(statusLabel(item.status))}</strong>
      <span>${integer(item.count)} bookings</span>
    </div>
  `).join("")}</div>`;
}

async function loadOverview() {
  try {
    const data = await api("/overview");
    if (!data.available || Number(data.totals.totalBookings) === 0) {
      loadOverviewEmptyState();
      return;
    }

    const customerEconomics = (data.customerEconomics || []).map((item) => ({
      currency: item.currency,
      bookings: Number(item.bookings || 0),
      revenueMinor: Number(item.revenue_minor || 0),
      processingMinor: Number(item.processing_minor || 0),
      profitMinor: Number(item.profit_minor || 0),
    }));
    const providerCosts = (data.providerCosts || []).map((item) => ({
      currency: item.currency,
      costMinor: Number(item.cost_minor || 0),
    }));
    const confirmed = Number(data.statuses.find((item) => item.status === "confirmed")?.count || 0);

    document.getElementById("overview-summary").innerHTML = [
      summaryCard({
        title: "Revenue",
        copy: "Customer charges grouped by the currency customers actually paid.",
        lines: renderSummaryLines(
          customerEconomics.map((item) => ({ label: item.currency, currency: item.currency, valueMinor: item.revenueMinor })),
          (item) => money(item.valueMinor, item.currency)
        ),
        accent: true,
      }),
      summaryCard({
        title: "Provider cost",
        copy: "Supplier payout totals in their original provider currency.",
        lines: renderSummaryLines(
          providerCosts.map((item) => ({ label: item.currency, currency: item.currency, valueMinor: item.costMinor })),
          (item) => money(item.valueMinor, item.currency)
        ),
      }),
      summaryCard({
        title: "Payment costs",
        copy: "Estimated card-processing costs by customer charge currency.",
        lines: renderSummaryLines(
          customerEconomics.map((item) => ({ label: item.currency, currency: item.currency, valueMinor: item.processingMinor })),
          (item) => money(item.valueMinor, item.currency)
        ),
      }),
      summaryCard({
        title: "Gross profit",
        copy: "Estimated Zippi profit after supplier cost and payment costs.",
        lines: renderSummaryLines(
          customerEconomics.map((item) => ({ label: item.currency, currency: item.currency, valueMinor: item.profitMinor })),
          (item) => money(item.valueMinor, item.currency)
        ),
        accent: true,
      }),
      summaryCard({
        title: "Average profit per booking",
        copy: "Average estimated profit across completed payments in each customer currency.",
        lines: renderSummaryLines(
          averageProfitItems(customerEconomics),
          (item) => money(item.valueMinor, item.currency)
        ),
      }),
    ].join("");

    document.getElementById("overview-operations").innerHTML = renderOperations([
      { label: "Booking sessions", value: Number(data.totals.totalBookings), note: "All flight booking sessions" },
      { label: "Confirmed bookings", value: confirmed, note: "Completed flight orders" },
      { label: "Flight ledger", value: Number(data.totals.flightBookings), note: "Bookings tracked in this admin" },
      { label: "Hotel commerce", value: "Not connected", note: "Hotels remain visible, but not bookable yet" },
    ]);
    document.getElementById("overview-statuses").innerHTML = renderStatuses(data.statuses || []);
  } catch (error) {
    document.getElementById("overview-summary").innerHTML = empty("Business summary unavailable", error.message);
    document.getElementById("overview-operations").innerHTML = empty("Operations unavailable", error.message);
    document.getElementById("overview-statuses").innerHTML = empty("Statuses unavailable", error.message);
  }
}

const configInputs = {
  fxMarginBps: ["fx-margin", 100],
  zippiMarkupBps: ["zippi-markup", 100],
  minGrossMarginMinor: ["min-margin", 100],
  zippiFeeMinor: ["booking-fee", 100],
  paymentProcessingPercentBps: ["processing-percent", 100],
  paymentProcessingFixedMinor: ["processing-fixed", 100],
  paymentProcessingCrossBorderBps: ["cross-border", 100],
};

function writeConfig(config) {
  Object.entries(configInputs).forEach(([key, [id, scale]]) => {
    document.getElementById(id).value = Number(config[key] || 0) / scale;
  });
}

function readConfig() {
  return {
    ...Object.fromEntries(
      Object.entries(configInputs).map(([key, [id, scale]]) => [
        key,
        Math.round(Number(document.getElementById(id).value) * scale),
      ])
    ),
  };
}

function writeCurrencyConfig(config) {
  supportedCurrencyCodes.forEach((code) => {
    document.getElementById(`currency-enabled-${code}`).checked = Boolean(config.currencies?.[code]?.enabled);
    document.getElementById(`currency-rounding-${code}`).value = Number(config.currencies?.[code]?.roundingIncrementMinor || 0) / minorFactor(code);
  });
  currencyRegions.forEach((region) => {
    document.getElementById(`currency-default-${region}`).value = config.defaultsByRegion?.[region] || "USD";
  });
}

function readCurrencyConfig() {
  return {
    currencies: Object.fromEntries(
      supportedCurrencyCodes.map((code) => [
        code,
        {
          enabled: document.getElementById(`currency-enabled-${code}`).checked,
          roundingIncrementMinor: Math.round(Number(document.getElementById(`currency-rounding-${code}`).value) * minorFactor(code)),
        },
      ])
    ),
    defaultsByRegion: Object.fromEntries(
      currencyRegions.map((region) => [
        region,
        document.getElementById(`currency-default-${region}`).value,
      ])
    ),
  };
}

async function loadConfig() {
  const data = await api("/config");
  state.config = data.flights.values;
  state.draft = data.flights.latestDraft;
  state.history = data.flights.history || [];
  state.currencyConfig = data.currencies?.values || null;
  state.currencyDraft = data.currencies?.latestDraft || null;
  state.currencyHistory = data.currencies?.history || [];
  state.currencyFx = data.currencies?.fx || null;
  state.currencySource = data.currencies?.source || null;
  state.currencyVersion = data.currencies?.version ?? null;
  writeConfig(state.draft?.config || state.config);
  if (state.currencyConfig) {
    writeCurrencyConfig(state.currencyDraft?.config || state.currencyConfig);
  }
  const source = document.getElementById("flight-config-source");
  source.textContent = data.flights.source === "centralized_active"
    ? "Live source: Active admin version"
    : "Live source: Render fallback";
  document.getElementById("config-version-label").textContent = data.flights.version == null
    ? "No active admin version yet"
    : `Active version ${data.flights.version}`;
  document.getElementById("live-state").textContent = data.flights.version == null ? "Fallback live" : "Live pricing";
  document.getElementById("draft-state").textContent = state.draft ? `Draft v${state.draft.version}` : "No draft";
  document.getElementById("draft-state").classList.toggle("draft", Boolean(state.draft));
  document.getElementById("review-active-draft").hidden = !state.draft;
  renderVersionHistory();
  updateChangedState();
  renderCurrencyState();
  schedulePreview();
}

function schedulePreview() {
  updateChangedState();
  clearTimeout(state.previewTimer);
  state.previewTimer = setTimeout(loadPreview, 180);
}

function updateChangedState() {
  if (!state.config) return;
  const current = readConfig();
  const changed = JSON.stringify(current) !== JSON.stringify(state.config);
  const chip = document.getElementById("changed-state");
  chip.textContent = changed ? "Preview edited" : "Preview unchanged";
  chip.classList.toggle("changed", changed);
}

function updateCurrencyChangedState() {
  if (!state.currencyConfig) return;
  const current = readCurrencyConfig();
  const changed = JSON.stringify(current) !== JSON.stringify(state.currencyConfig);
  const chip = document.getElementById("currency-changed-state");
  chip.textContent = changed ? "Preview edited" : "Preview unchanged";
  chip.classList.toggle("changed", changed);
}

function renderVersionHistory() {
  const container = document.getElementById("pricing-version-history");
  if (!state.history.length) {
    container.innerHTML = `<div class="empty-state">No centralized pricing versions yet. Render fallback pricing is still live.</div>`;
    return;
  }
  container.innerHTML = state.history.map((version) => `
    <div class="version-row">
      <span class="version-status ${escapeHtml(version.status)}">${escapeHtml(version.status)}</span>
      <div>
        <strong>Version ${integer(version.version)}</strong>
        <p>${escapeHtml(
          version.activated_at
            ? `Activated ${new Date(version.activated_at).toLocaleString()}`
            : `Saved ${new Date(version.created_at).toLocaleString()}`
        )}${version.based_on_version ? ` · based on v${integer(version.based_on_version)}` : ""}</p>
      </div>
      ${version.status === "active" || version.status === "draft"
        ? ""
        : `<button type="button" class="rollback-button" data-rollback-version="${integer(version.version)}">Review restore</button>`}
    </div>
  `).join("");
  container.querySelectorAll("[data-rollback-version]").forEach((button) => {
    button.addEventListener("click", () => reviewPricingAction("rollback", Number(button.dataset.rollbackVersion)));
  });
}

function renderCurrencyState() {
  if (!state.currencyConfig) return;
  const source = document.getElementById("currency-config-source");
  source.textContent = state.currencySource === "centralized_active"
    ? "Live source: Active admin version"
    : "Live source: Render fallback";
  document.getElementById("currency-version-label").textContent = state.currencyVersion == null
    ? "No active admin version yet"
    : `Active version ${state.currencyVersion}`;
  document.getElementById("currency-draft-state").textContent = state.currencyDraft ? `Draft v${state.currencyDraft.version}` : "No draft";
  document.getElementById("currency-draft-state").classList.toggle("draft", Boolean(state.currencyDraft));
  document.getElementById("review-active-currency-draft").hidden = !state.currencyDraft;
  renderCurrencyHistory();
  renderCurrencyOperational();
  updateCurrencyChangedState();
}

function renderCurrencyHistory() {
  const container = document.getElementById("currency-version-history");
  if (!state.currencyHistory.length) {
    container.innerHTML = `<div class="empty-state">No centralized currency versions yet. Render fallback settings are still live.</div>`;
    return;
  }
  container.innerHTML = state.currencyHistory.map((version) => `
    <div class="version-row">
      <span class="version-status ${escapeHtml(version.status)}">${escapeHtml(version.status)}</span>
      <div>
        <strong>Version ${integer(version.version)}</strong>
        <p>${escapeHtml(
          version.activated_at
            ? `Activated ${new Date(version.activated_at).toLocaleString()}`
            : `Saved ${new Date(version.created_at).toLocaleString()}`
        )}${version.based_on_version ? ` · based on v${integer(version.based_on_version)}` : ""}</p>
      </div>
      ${version.status === "active" || version.status === "draft"
        ? ""
        : `<button type="button" class="rollback-button" data-currency-rollback-version="${integer(version.version)}">Restore</button>`}
    </div>
  `).join("");
  container.querySelectorAll("[data-currency-rollback-version]").forEach((button) => {
    button.addEventListener("click", () => reviewCurrencyAction("rollback", Number(button.dataset.currencyRollbackVersion)));
  });
}

function renderCurrencyOperational() {
  const target = document.getElementById("currency-operational");
  if (!state.currencyFx) {
    target.innerHTML = empty("FX status unavailable", "Operational FX health will appear here.");
    return;
  }
  const representative = Object.entries(state.currencyFx.representativeRates || {}).map(([code, value]) => ({
    code,
    value,
  }));
  target.innerHTML = `
    <div class="currency-ops-grid">
      <div class="operation-card">
        <span>FX source</span>
        <strong>${escapeHtml(state.currencyFx.source || "Unavailable")}</strong>
        <small>${state.currencyFx.stale ? "Using cached fallback rates" : "Live cached FX feed"}</small>
      </div>
      <div class="operation-card">
        <span>Last successful update</span>
        <strong>${escapeHtml(state.currencyFx.updatedAt ? new Date(state.currencyFx.updatedAt).toLocaleString() : "Unavailable")}</strong>
        <small>Automatic refresh, no manual rate entry</small>
      </div>
      <div class="operation-card">
        <span>FX service health</span>
        <strong>${escapeHtml(state.currencyFx.stale ? "Degraded" : "Healthy")}</strong>
        <small>${escapeHtml(state.currencyFx.stale ? "Serving cached rates until refresh succeeds" : "Cached rates are current")}</small>
      </div>
    </div>
    <div class="currency-rates">
      ${representative.map((item) => `
        <div class="rate-pill">
          <span>${escapeHtml(item.code)}</span>
          <strong>${item.value == null ? "Unavailable" : escapeHtml(String(item.value))}</strong>
        </div>
      `).join("")}
    </div>
  `;
}

function pricingNarrative(customer, provider) {
  if (customer.currency === provider.currency) {
    return `Customers would be charged in ${customer.currency}. The supplier is also paid in ${provider.currency}.`;
  }
  return `Customers would be charged in ${customer.currency}. The supplier still gets paid in ${provider.currency}.`;
}

async function loadPreview() {
  const container = document.getElementById("pricing-preview");
  container.className = "preview-loading";
  container.textContent = "Calculating with the backend pricing engine...";
  try {
    const data = await api("/flights/preview", {
      method: "POST",
      body: JSON.stringify({
        providerAmount: document.getElementById("provider-amount").value,
        providerCurrency: document.getElementById("provider-currency").value,
        customerCurrency: document.getElementById("customer-currency").value,
        config: readConfig(),
      }),
    });
    const quote = data.quote;
    const customer = quote.customer;
    const provider = quote.provider;
    const lines = customer.lineItems;
    const profitPercent = customer.totalMinor > 0
      ? (lines.estimatedGrossMarginMinor / customer.totalMinor * 100).toFixed(1)
      : "0.0";
    container.className = "";
    container.innerHTML = `
      <div class="price-hero">
        <small>Customer checkout total</small>
        <strong>${money(customer.totalMinor, customer.currency)}</strong>
        <p>${escapeHtml(pricingNarrative(customer, provider))}</p>
      </div>
      <div class="preview-highlights">
        <div class="highlight-card gold">
          <span>Estimated Zippi Profit</span>
          <strong>${money(lines.estimatedGrossMarginMinor, customer.currency)}</strong>
        </div>
        <div class="highlight-card">
          <span>Profit Margin</span>
          <strong>${escapeHtml(`${profitPercent}%`)}</strong>
        </div>
      </div>
      <div class="preview-callout">This sample uses the real backend pricing engine, but it stays private until you activate a reviewed version.</div>
      <div class="breakdown">
        ${breakdown("Supplier cost", money(provider.totalMinor, provider.currency))}
        ${breakdown("Converted supplier cost", money(lines.rawConvertedMinor, customer.currency))}
        ${breakdown("Currency safety buffer", money(lines.fxProtectionMinor, customer.currency))}
        ${breakdown("Zippi profit markup", money(lines.zippiMarkupMinor, customer.currency))}
        ${breakdown("Zippi booking fee", money(lines.zippiFeeMinor, customer.currency))}
        ${breakdown("Card processing allowance", money(lines.paymentProcessingAllowanceMinor, customer.currency))}
        ${breakdown("Estimated card processing cost", money(lines.estimatedProcessingMinor, customer.currency))}
        ${breakdown("Minimum profit target top-up", money(lines.minMarginTopUpMinor, customer.currency))}
        ${breakdown("Round-up adjustment", money(lines.roundingAdjustmentMinor, customer.currency))}
      </div>
    `;
  } catch (error) {
    container.innerHTML = empty("Preview unavailable", error.message);
  }
}

function breakdown(label, value) {
  return `<div class="breakdown-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

async function saveDraft() {
  if (!window.confirm("Save these flight pricing settings as a private draft? This will not change live checkout.")) return;
  const button = document.getElementById("save-flight-draft");
  button.disabled = true;
  try {
    const data = await api("/flights/config/drafts", {
      method: "POST",
      body: JSON.stringify({ config: readConfig(), confirmed: true }),
    });
    toast(`Draft version ${data.draft.version} saved. Live checkout did not change.`);
    await loadConfig();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
}

async function loadCurrencies() {
  renderCurrencyState();
}

async function saveCurrencyDraft() {
  if (!window.confirm("Save these shared currency settings as a private draft? This will not change live checkout until you activate it.")) return;
  const button = document.getElementById("save-currency-draft");
  button.disabled = true;
  try {
    const data = await api("/currencies/config/drafts", {
      method: "POST",
      body: JSON.stringify({ config: readCurrencyConfig(), confirmed: true }),
    });
    toast(`Currency draft version ${data.draft.version} saved. Live checkout did not change.`);
    await loadConfig();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
}

function configFieldLabel(field) {
  if (field === "fxMarginBps") return "Currency safety buffer";
  if (field === "zippiMarkupBps") return "Zippi profit markup";
  if (field === "minGrossMarginMinor") return "Minimum profit target";
  if (field === "zippiFeeMinor") return "Zippi booking fee";
  if (field === "paymentProcessingPercentBps") return "Card processing %";
  if (field === "paymentProcessingFixedMinor") return "Card processing fixed fee";
  if (field === "paymentProcessingCrossBorderBps") return "International card buffer";
  return field;
}

function configValue(field, value, currency = "CAD") {
  if (field.endsWith("Bps")) return `${(Number(value) / 100).toFixed(2).replace(/\.00$/, "")}%`;
  if (field.endsWith("Minor")) return money(value, currency);
  if (field.startsWith("roundingRules.")) return money(value, field.split(".")[1]);
  return String(value);
}

function currencyFieldLabel(field) {
  if (field.startsWith("currencies.") && field.endsWith(".enabled")) {
    return `${field.split(".")[1]} enabled for checkout`;
  }
  if (field.startsWith("currencies.") && field.endsWith(".roundingIncrementMinor")) {
    return `${field.split(".")[1]} round final price to`;
  }
  if (field.startsWith("defaultsByRegion.")) {
    const region = field.split(".")[1];
    const labelMap = {
      CA: "Canada default",
      US: "United States default",
      EU: "Euro area default",
      CO: "Colombia default",
      DEFAULT: "Fallback default",
    };
    return labelMap[region] || field;
  }
  return field;
}

function currencyFieldValue(field, value) {
  if (field.endsWith(".enabled")) return value ? "Enabled" : "Disabled";
  if (field.endsWith(".roundingIncrementMinor")) {
    const code = field.split(".")[1];
    return money(value, code);
  }
  return String(value);
}

async function reviewPricingAction(action, version) {
  const dialog = document.getElementById("pricing-action-dialog");
  const detail = document.getElementById("pricing-action-detail");
  detail.innerHTML = `<div class="pricing-review"><p class="eyebrow">Loading comparison</p><h2>Reviewing pricing version...</h2></div>`;
  dialog.showModal();
  try {
    const basePath = action === "activate"
      ? `/flights/config/drafts/${version}/review`
      : `/flights/config/versions/${version}/review`;
    const review = await api(basePath, {
      method: "POST",
      body: JSON.stringify({
        providerAmount: document.getElementById("provider-amount").value,
        providerCurrency: document.getElementById("provider-currency").value,
        customerCurrency: document.getElementById("customer-currency").value,
      }),
    });
    const current = review.current.quote.customer;
    const candidate = review.candidate.quote.customer;
    const customerCurrency = candidate.currency;
    const changes = review.changes.length
      ? review.changes.map((change) => `
        <div class="change-row">
          <span>${escapeHtml(configFieldLabel(change.field))}</span>
          <strong>${escapeHtml(configValue(change.field, change.from, customerCurrency))} &rarr; ${escapeHtml(configValue(change.field, change.to, customerCurrency))}</strong>
        </div>
      `).join("")
      : `<div class="change-row"><span>Pricing settings</span><strong>No numerical change</strong></div>`;
    const actionLabel = action === "activate" ? "Activate draft" : "Restore version";
    detail.innerHTML = `
      <div class="pricing-review">
        <p class="eyebrow">Explicit confirmation</p>
        <h2>${action === "activate" ? `Activate draft v${version}?` : `Restore version v${version}?`}</h2>
        <p>This comparison uses the backend pricing engine with the current sample. Past bookings will not change.</p>
        <div class="review-comparison">
          <div class="review-price">
            <small>Current sample</small>
            <strong>${money(current.totalMinor, current.currency)}</strong>
            <p>Estimated profit ${money(current.lineItems.estimatedGrossMarginMinor, current.currency)}</p>
          </div>
          <div class="review-price candidate">
            <small>Proposed sample</small>
            <strong>${money(candidate.totalMinor, candidate.currency)}</strong>
            <p>Estimated profit ${money(candidate.lineItems.estimatedGrossMarginMinor, candidate.currency)}</p>
          </div>
        </div>
        <div class="change-list">${changes}</div>
        <div class="action-warning">Only future quotes use the new active version. Existing bookings keep their saved pricing snapshot.</div>
        <div class="dialog-actions">
          <button type="button" class="secondary-button" id="cancel-pricing-action">Cancel</button>
          <button type="button" class="primary-button compact" id="confirm-pricing-action">${actionLabel}</button>
        </div>
      </div>
    `;
    document.getElementById("cancel-pricing-action").addEventListener("click", () => dialog.close());
    document.getElementById("confirm-pricing-action").addEventListener("click", () => performPricingAction(action, version));
  } catch (error) {
    detail.innerHTML = `<div class="pricing-review"><h2>Review unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function performPricingAction(action, version) {
  const button = document.getElementById("confirm-pricing-action");
  button.disabled = true;
  try {
    const path = action === "activate"
      ? `/flights/config/drafts/${version}/activate`
      : `/flights/config/versions/${version}/rollback`;
    const data = await api(path, {
      method: "POST",
      body: JSON.stringify({ confirmed: true, reviewedVersion: version }),
    });
    document.getElementById("pricing-action-dialog").close();
    toast(`Pricing version ${data.active.version} is now live.`);
    await loadConfig();
  } catch (error) {
    toast(error.message);
    button.disabled = false;
  }
}

async function reviewCurrencyAction(action, version) {
  const dialog = document.getElementById("pricing-action-dialog");
  const detail = document.getElementById("pricing-action-detail");
  detail.innerHTML = `<div class="pricing-review"><p class="eyebrow">Loading comparison</p><h2>Reviewing currency version...</h2></div>`;
  dialog.showModal();
  try {
    const basePath = action === "activate"
      ? `/currencies/config/drafts/${version}/review`
      : `/currencies/config/versions/${version}/review`;
    const review = await api(basePath, { method: "POST", body: JSON.stringify({}) });
    const changes = review.changes.length
      ? review.changes.map((change) => `
        <div class="change-row">
          <span>${escapeHtml(currencyFieldLabel(change.field))}</span>
          <strong>${escapeHtml(currencyFieldValue(change.field, change.from))} &rarr; ${escapeHtml(currencyFieldValue(change.field, change.to))}</strong>
        </div>
      `).join("")
      : `<div class="change-row"><span>Currency settings</span><strong>No numerical change</strong></div>`;
    const actionLabel = action === "activate" ? "Activate draft" : "Restore version";
    detail.innerHTML = `
      <div class="pricing-review">
        <p class="eyebrow">Explicit confirmation</p>
        <h2>${action === "activate" ? `Activate currency draft v${version}?` : `Restore currency version v${version}?`}</h2>
        <p>These settings will change enabled currencies, defaults, and final round-up rules for every platform that consumes the shared backend contract.</p>
        <div class="change-list">${changes}</div>
        <div class="action-warning">Customer price calculations stay backend-owned. Activating this draft affects future searches and quotes only.</div>
        <div class="dialog-actions">
          <button type="button" class="secondary-button" id="cancel-pricing-action">Cancel</button>
          <button type="button" class="primary-button compact" id="confirm-pricing-action">${actionLabel}</button>
        </div>
      </div>
    `;
    document.getElementById("cancel-pricing-action").addEventListener("click", () => dialog.close());
    document.getElementById("confirm-pricing-action").addEventListener("click", () => performCurrencyAction(action, version));
  } catch (error) {
    detail.innerHTML = `<div class="pricing-review"><h2>Review unavailable</h2><p>${escapeHtml(error.message)}</p></div>`;
  }
}

async function performCurrencyAction(action, version) {
  const button = document.getElementById("confirm-pricing-action");
  button.disabled = true;
  try {
    const path = action === "activate"
      ? `/currencies/config/drafts/${version}/activate`
      : `/currencies/config/versions/${version}/rollback`;
    const data = await api(path, {
      method: "POST",
      body: JSON.stringify({ confirmed: true, reviewedVersion: version }),
    });
    document.getElementById("pricing-action-dialog").close();
    toast(`Currency version ${data.active.version} is now live.`);
    await loadConfig();
  } catch (error) {
    toast(error.message);
    button.disabled = false;
  }
}

function statusLabel(status) {
  return String(status || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

async function loadFlightBookings() {
  const container = document.getElementById("flight-booking-list");
  try {
    const data = await api("/flights/bookings");
    if (!data.bookings.length) {
      container.innerHTML = empty("No flight booking sessions", "Real bookings will appear here as they are created.");
      return;
    }
    container.innerHTML = data.bookings.map((booking) => `
      <button class="booking-card" type="button" data-booking-id="${escapeHtml(booking.id)}">
        <span class="booking-route">
          <strong>${escapeHtml(booking.route)}</strong>
          <small>${new Date(booking.createdAt).toLocaleString()}</small>
        </span>
        <span>
          <span class="status ${escapeHtml(booking.status)}">${escapeHtml(statusLabel(booking.status))}</span>
          <small>Booking status</small>
        </span>
        <span class="booking-metric">
          <strong>${money(booking.customer.totalMinor, booking.customer.currency)}</strong>
          <small>Customer paid</small>
        </span>
        <span class="booking-metric">
          <strong>${money(booking.provider.totalMinor, booking.provider.currency)}</strong>
          <small>Provider cost</small>
        </span>
        <span class="booking-metric">
          <strong>${booking.estimatedProfitMinor == null ? "Not available" : money(booking.estimatedProfitMinor, booking.customer.currency)}</strong>
          <small>Estimated profit</small>
        </span>
        <span class="booking-metric">
          <strong>${booking.profitPercent == null ? "Not available" : `${booking.profitPercent}%`}</strong>
          <small>Profit margin</small>
        </span>
        <span class="booking-reference">
          <strong>${escapeHtml(booking.bookingReference || "Pending")}</strong>
          <small>Booking reference</small>
        </span>
      </button>
    `).join("");
    container.querySelectorAll("[data-booking-id]").forEach((button) => {
      button.addEventListener("click", () => openBooking(button.dataset.bookingId));
    });
  } catch (error) {
    container.innerHTML = empty("Bookings unavailable", error.message);
  }
}

async function openBooking(id) {
  try {
    const data = await api(`/flights/bookings/${encodeURIComponent(id)}`);
    const booking = data.booking;
    const e = booking.economics;
    const fields = [
      ["Status", booking.status],
      ["Customer paid", money(booking.customer.totalMinor, booking.customer.currency)],
      ["Provider cost", money(booking.provider.totalMinor, booking.provider.currency)],
      ["FX rate", e.customer_fx_rate || "Not available"],
      ["Currency safety buffer", money(e.customer_fx_protection_minor, booking.customer.currency)],
      ["Zippi profit markup", money(e.customer_zippi_markup_minor, booking.customer.currency)],
      ["Zippi booking fee", money(e.customer_zippi_fee_minor, booking.customer.currency)],
      ["Card processing allowance", money(e.customer_payment_processing_allowance_minor, booking.customer.currency)],
      ["Estimated card processing cost", money(e.customer_estimated_processing_minor, booking.customer.currency)],
      ["Minimum profit target top-up", money(e.customer_min_margin_top_up_minor, booking.customer.currency)],
      ["Round-up adjustment", money(e.customer_rounding_adjustment_minor, booking.customer.currency)],
      ["Estimated Zippi profit", money(e.customer_estimated_gross_margin_minor, booking.customer.currency)],
      ["Pricing source", booking.pricingConfig.source],
      ["Pricing version", booking.pricingConfig.version == null ? "Legacy or environment fallback" : `Version ${booking.pricingConfig.version}`],
      ["Booking reference", booking.bookingReference || "Not assigned"],
      ["Session ID", booking.id],
    ];
    document.getElementById("booking-detail").innerHTML = `
      <div class="detail-content">
        <p class="eyebrow">Saved pricing snapshot</p>
        <h2>${escapeHtml(booking.route)}</h2>
        <div class="detail-grid">
          ${fields.map(([label, value]) => `
            <div class="detail-item">
              <small>${escapeHtml(label)}</small>
              <strong>${escapeHtml(value)}</strong>
            </div>
          `).join("")}
        </div>
      </div>
    `;
    document.getElementById("booking-dialog").showModal();
  } catch (error) {
    toast(error.message);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll("a[data-route]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      navigate(link.dataset.route);
    });
  });
  window.addEventListener("popstate", () => navigate(routeFromPath(location.pathname), false));
  document.getElementById("flight-pricing-form").addEventListener("input", schedulePreview);
  document.getElementById("provider-amount").addEventListener("input", schedulePreview);
  document.getElementById("provider-currency").addEventListener("change", schedulePreview);
  document.getElementById("customer-currency").addEventListener("change", schedulePreview);
  document.getElementById("currency-settings-form").addEventListener("input", updateCurrencyChangedState);
  document.getElementById("currency-settings-form").addEventListener("change", updateCurrencyChangedState);
  document.getElementById("reset-flight-config").addEventListener("click", () => {
    writeConfig(state.config);
    schedulePreview();
  });
  document.getElementById("reset-currency-config").addEventListener("click", () => {
    writeCurrencyConfig(state.currencyConfig);
    updateCurrencyChangedState();
  });
  document.getElementById("save-flight-draft").addEventListener("click", saveDraft);
  document.getElementById("save-currency-draft").addEventListener("click", saveCurrencyDraft);
  document.getElementById("review-active-draft").addEventListener("click", () => {
    if (state.draft) reviewPricingAction("activate", Number(state.draft.version));
  });
  document.getElementById("review-active-currency-draft").addEventListener("click", () => {
    if (state.currencyDraft) reviewCurrencyAction("activate", Number(state.currencyDraft.version));
  });
  document.querySelector(".dialog-close").addEventListener("click", () => document.getElementById("booking-dialog").close());
  document.querySelector(".pricing-dialog-close").addEventListener("click", () => document.getElementById("pricing-action-dialog").close());
  try {
    await loadConfig();
  } catch (error) {
    toast(error.message);
  }
  navigate(routeFromPath(location.pathname), false);
});
