const state = { config: null, draft: null, history: [], route: null, previewTimer: null };

const pages = {
  overview: { title: "Overview", path: "/admin/overview" },
  flights: { title: "Flights pricing", path: "/admin/flights" },
  "flight-bookings": { title: "Flight bookings", path: "/admin/flights/bookings" },
  hotels: { title: "Hotels pricing", path: "/admin/hotels" },
  "hotel-bookings": { title: "Hotel bookings", path: "/admin/hotels/bookings" },
};

function routeFromPath(pathname) {
  if (pathname.includes("/flights/bookings")) return "flight-bookings";
  if (pathname.includes("/hotels/bookings")) return "hotel-bookings";
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
  document.querySelectorAll("[data-page]").forEach((element) => { element.hidden = element.dataset.page !== route; });
  document.querySelectorAll("nav a[data-route]").forEach((element) => element.classList.toggle("active", element.dataset.route === route));
  document.getElementById("page-title").textContent = pages[route].title;
  if (push) history.pushState({ route }, "", pages[route].path);
  if (route === "overview") loadOverview();
  if (route === "flight-bookings") loadFlightBookings();
}

function minorFactor(currency) { return ["JPY", "KRW", "VND"].includes(String(currency).toUpperCase()) ? 1 : 100; }
function money(minor, currency) {
  if (minor == null || !currency) return "Not available";
  return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: 2 }).format(Number(minor) / minorFactor(currency));
}
function integer(value) { return new Intl.NumberFormat().format(Number(value || 0)); }
function escapeHtml(value) { const node = document.createElement("span"); node.textContent = String(value ?? ""); return node.innerHTML; }
function toast(message) { const element = document.getElementById("toast"); element.textContent = message; element.classList.add("visible"); setTimeout(() => element.classList.remove("visible"), 3200); }

async function loadOverview() {
  const metrics = document.getElementById("overview-metrics");
  try {
    const data = await api("/overview");
    if (!data.available || data.totals.totalBookings === 0) {
      metrics.innerHTML = metricCards(0, 0, 0, 0);
      document.getElementById("customer-economics").innerHTML = empty("No flight revenue yet", "Economics will appear after the first booking session.");
      document.getElementById("provider-costs").innerHTML = empty("No provider costs yet", "Supplier totals stay grouped by their original currency.");
      return;
    }
    const confirmed = data.statuses.find((item) => item.status === "confirmed")?.count || 0;
    metrics.innerHTML = metricCards(data.totals.totalBookings, confirmed, data.totals.flightBookings, data.totals.hotelBookings);
    document.getElementById("customer-economics").innerHTML = data.customerEconomics.map((item) => `
      <div class="economics-row"><div><strong>${escapeHtml(item.currency)}</strong><small>${integer(item.bookings)} booking sessions</small></div>
      <span>${money(item.revenue_minor,item.currency)}<small>revenue</small></span><span>${money(item.processing_minor,item.currency)}<small>processing</small></span><span>${money(item.profit_minor,item.currency)}<small>estimated profit</small></span></div>`).join("");
    document.getElementById("provider-costs").innerHTML = data.providerCosts.map((item) => `
      <div class="economics-row"><div><strong>${escapeHtml(item.currency)}</strong><small>Original provider currency</small></div><span>${money(item.cost_minor,item.currency)}<small>provider cost</small></span></div>`).join("");
  } catch (error) {
    metrics.innerHTML = empty("Economics unavailable", error.message);
  }
}

function metricCards(total, confirmed, flights, hotels) {
  return `<article class="metric-card accent"><p>Total booking sessions</p><strong>${integer(total)}</strong><small>All statuses</small></article>
    <article class="metric-card"><p>Confirmed bookings</p><strong>${integer(confirmed)}</strong><small>Completed flight orders</small></article>
    <article class="metric-card"><p>Flight bookings</p><strong>${integer(flights)}</strong><small>Existing ledger</small></article>
    <article class="metric-card"><p>Hotel bookings</p><strong>${integer(hotels)}</strong><small>Ledger not connected</small></article>`;
}
function empty(title, copy) { return `<div class="empty-state"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(copy)}</p></div>`; }

const configInputs = {
  fxMarginBps: ["fx-margin", 100], zippiMarkupBps: ["zippi-markup", 100],
  minGrossMarginMinor: ["min-margin", 100], zippiFeeMinor: ["booking-fee", 100],
  paymentProcessingPercentBps: ["processing-percent", 100], paymentProcessingFixedMinor: ["processing-fixed", 100],
  paymentProcessingCrossBorderBps: ["cross-border", 100],
};
function writeConfig(config) {
  Object.entries(configInputs).forEach(([key,[id,scale]]) => { document.getElementById(id).value = Number(config[key] || 0) / scale; });
  document.getElementById("rounding-major").value = Number(config.roundingRules?.CAD || 500) / 100;
  document.getElementById("rounding-cop").value = Number(config.roundingRules?.COP || 50000) / 100;
}
function readConfig() {
  return {
    ...Object.fromEntries(Object.entries(configInputs).map(([key,[id,scale]]) => [key, Math.round(Number(document.getElementById(id).value) * scale)])),
    roundingRules: {
      CAD: Math.round(Number(document.getElementById("rounding-major").value) * 100),
      USD: Math.round(Number(document.getElementById("rounding-major").value) * 100),
      EUR: Math.round(Number(document.getElementById("rounding-major").value) * 100),
      COP: Math.round(Number(document.getElementById("rounding-cop").value) * 100),
    },
  };
}

async function loadConfig() {
  const data = await api("/config");
  state.config = data.flights.values;
  state.draft = data.flights.latestDraft;
  state.history = data.flights.history || [];
  writeConfig(state.draft?.config || state.config);
  const source = document.getElementById("flight-config-source");
  source.textContent = data.flights.source === "centralized_active" ? "Centralized live pricing" : "Environment fallback live";
  document.getElementById("config-version-label").textContent = data.flights.version == null
    ? "No centralized active version"
    : `Active version ${data.flights.version}`;
  document.getElementById("draft-state").textContent = state.draft ? `Draft v${state.draft.version}` : "No draft";
  document.getElementById("draft-state").classList.toggle("draft", Boolean(state.draft));
  document.getElementById("review-active-draft").hidden = !state.draft;
  renderVersionHistory();
  updateChangedState();
  schedulePreview();
}
function schedulePreview() { updateChangedState(); clearTimeout(state.previewTimer); state.previewTimer = setTimeout(loadPreview, 180); }
function updateChangedState() {
  if (!state.config) return;
  const current = readConfig();
  const changed = JSON.stringify(current) !== JSON.stringify(state.config);
  const chip = document.getElementById("changed-state");
  chip.textContent = changed ? "Changed" : "Unchanged";
  chip.classList.toggle("changed", changed);
}

function renderVersionHistory() {
  const container = document.getElementById("pricing-version-history");
  if (!state.history.length) {
    container.innerHTML = `<div class="empty-state">No centralized pricing versions yet. Environment fallback is live.</div>`;
    return;
  }
  container.innerHTML = state.history.map((version) => `<div class="version-row">
    <span class="version-status ${escapeHtml(version.status)}">${escapeHtml(version.status)}</span>
    <div><strong>Version ${integer(version.version)}</strong><p>${escapeHtml(version.activated_at ? `Activated ${new Date(version.activated_at).toLocaleString()}` : `Saved ${new Date(version.created_at).toLocaleString()}`)}${version.based_on_version ? ` · based on v${integer(version.based_on_version)}` : ""}</p></div>
    ${version.status === "active" || version.status === "draft" ? "" : `<button type="button" class="rollback-button" data-rollback-version="${integer(version.version)}">Review rollback</button>`}
  </div>`).join("");
  container.querySelectorAll("[data-rollback-version]").forEach((button) => button.addEventListener("click", () => reviewPricingAction("rollback", Number(button.dataset.rollbackVersion))));
}
async function loadPreview() {
  const container = document.getElementById("pricing-preview");
  container.className = "preview-loading";
  container.textContent = "Calculating with the backend pricing engine...";
  try {
    const data = await api("/flights/preview", { method: "POST", body: JSON.stringify({
      providerAmount: document.getElementById("provider-amount").value,
      providerCurrency: document.getElementById("provider-currency").value,
      customerCurrency: document.getElementById("customer-currency").value,
      config: readConfig(),
    }) });
    const quote = data.quote; const customer = quote.customer; const provider = quote.provider; const lines = customer.lineItems;
    const profitPercent = customer.totalMinor > 0 ? (lines.estimatedGrossMarginMinor / customer.totalMinor * 100).toFixed(1) : "0.0";
    container.className = "";
    container.innerHTML = `<div class="price-hero"><small>Final customer price</small><strong>${money(customer.totalMinor,customer.currency)}</strong><p>Stripe charge currency: ${escapeHtml(customer.currency)}</p></div>
      <div class="breakdown">
      ${breakdown("Provider cost",money(provider.totalMinor,provider.currency))}
      ${breakdown("Converted provider cost",money(lines.rawConvertedMinor,customer.currency))}
      ${breakdown("FX protection",money(lines.fxProtectionMinor,customer.currency))}
      ${breakdown("Zippi markup",money(lines.zippiMarkupMinor,customer.currency))}
      ${breakdown("Booking fee",money(lines.zippiFeeMinor,customer.currency))}
      ${breakdown("Processing allowance",money(lines.paymentProcessingAllowanceMinor,customer.currency))}
      ${breakdown("Estimated processing cost",money(lines.estimatedProcessingMinor,customer.currency))}
      ${breakdown("Minimum-margin adjustment",money(lines.minMarginTopUpMinor,customer.currency))}
      ${breakdown("Rounding adjustment",money(lines.roundingAdjustmentMinor,customer.currency))}
      <div class="breakdown-row profit"><span>Estimated Zippi profit</span><strong>${money(lines.estimatedGrossMarginMinor,customer.currency)} · ${profitPercent}%</strong></div></div>`;
  } catch (error) { container.innerHTML = empty("Preview unavailable",error.message); }
}
function breakdown(label,value) { return `<div class="breakdown-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`; }

async function saveDraft() {
  if (!window.confirm("Save these flight pricing values as a versioned draft? This will not change live pricing.")) return;
  const button = document.getElementById("save-flight-draft"); button.disabled = true;
  try {
    const data = await api("/flights/config/drafts", { method: "POST", body: JSON.stringify({ config: readConfig(), confirmed: true }) });
    toast(`Draft version ${data.draft.version} saved. Live pricing was not changed.`);
    await loadConfig();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
}

const configLabels = {
  fxMarginBps: "FX protection", zippiMarkupBps: "Zippi markup", minGrossMarginMinor: "Minimum margin",
  zippiFeeMinor: "Booking fee", paymentProcessingPercentBps: "Processing allowance",
  paymentProcessingFixedMinor: "Fixed processing cost", paymentProcessingCrossBorderBps: "Cross-border allowance",
};
function configValue(field, value, currency = "CAD") {
  if (field.endsWith("Bps")) return `${(Number(value) / 100).toFixed(2).replace(/\.00$/, "")}%`;
  if (field.endsWith("Minor")) return money(value, currency);
  if (field.startsWith("roundingRules.")) return money(value, field.split(".")[1]);
  return String(value);
}

async function reviewPricingAction(action, version) {
  const dialog = document.getElementById("pricing-action-dialog");
  const detail = document.getElementById("pricing-action-detail");
  detail.innerHTML = `<div class="pricing-review"><p class="eyebrow">Loading comparison</p><h2>Reviewing pricing version...</h2></div>`;
  dialog.showModal();
  try {
    const basePath = action === "activate" ? `/flights/config/drafts/${version}/review` : `/flights/config/versions/${version}/review`;
    const review = await api(basePath, { method: "POST", body: JSON.stringify({
      providerAmount: document.getElementById("provider-amount").value,
      providerCurrency: document.getElementById("provider-currency").value,
      customerCurrency: document.getElementById("customer-currency").value,
    }) });
    const current = review.current.quote.customer; const candidate = review.candidate.quote.customer;
    const customerCurrency = candidate.currency;
    const changes = review.changes.length ? review.changes.map((change) => `<div class="change-row"><span>${escapeHtml(configLabels[change.field] || change.field)}</span><strong>${escapeHtml(configValue(change.field,change.from,customerCurrency))} &rarr; ${escapeHtml(configValue(change.field,change.to,customerCurrency))}</strong></div>`).join("") : `<div class="change-row"><span>Pricing controls</span><strong>No numerical change</strong></div>`;
    const actionLabel = action === "activate" ? "Activate draft" : "Activate rollback";
    detail.innerHTML = `<div class="pricing-review"><p class="eyebrow">Explicit confirmation</p><h2>${action === "activate" ? `Activate draft v${version}?` : `Roll back to version v${version}?`}</h2>
      <p>This comparison uses the backend pricing engine with the current sample. Existing bookings will not change.</p>
      <div class="review-comparison"><div class="review-price"><small>Current sample</small><strong>${money(current.totalMinor,current.currency)}</strong><p>Profit ${money(current.lineItems.estimatedGrossMarginMinor,current.currency)}</p></div>
      <div class="review-price candidate"><small>Proposed sample</small><strong>${money(candidate.totalMinor,candidate.currency)}</strong><p>Profit ${money(candidate.lineItems.estimatedGrossMarginMinor,candidate.currency)}</p></div></div>
      <div class="change-list">${changes}</div><div class="action-warning">This action changes pricing for subsequent quotes only. It creates a new active version and retains history.</div>
      <div class="dialog-actions"><button type="button" class="secondary-button" id="cancel-pricing-action">Cancel</button><button type="button" class="primary-button compact" id="confirm-pricing-action">${actionLabel}</button></div></div>`;
    document.getElementById("cancel-pricing-action").addEventListener("click", () => dialog.close());
    document.getElementById("confirm-pricing-action").addEventListener("click", () => performPricingAction(action, version));
  } catch (error) { detail.innerHTML = `<div class="pricing-review"><h2>Review unavailable</h2><p>${escapeHtml(error.message)}</p></div>`; }
}

async function performPricingAction(action, version) {
  const button = document.getElementById("confirm-pricing-action"); button.disabled = true;
  try {
    const path = action === "activate" ? `/flights/config/drafts/${version}/activate` : `/flights/config/versions/${version}/rollback`;
    const data = await api(path, { method: "POST", body: JSON.stringify({ confirmed: true, reviewedVersion: version }) });
    document.getElementById("pricing-action-dialog").close();
    toast(`Pricing version ${data.active.version} is now live.`);
    await loadConfig();
  } catch (error) { toast(error.message); button.disabled = false; }
}

async function loadFlightBookings() {
  const container = document.getElementById("flight-booking-list");
  try {
    const data = await api("/flights/bookings");
    if (!data.bookings.length) { container.innerHTML = empty("No flight booking sessions", "Real bookings will appear here as they are created."); return; }
    container.innerHTML = data.bookings.map((booking) => `<button class="booking-card" type="button" data-booking-id="${escapeHtml(booking.id)}">
      <span><strong>${escapeHtml(booking.route)}</strong><small>${new Date(booking.createdAt).toLocaleString()}</small></span>
      <span class="status ${escapeHtml(booking.status)}">${escapeHtml(booking.status.replaceAll("_"," "))}</span>
      <span>${money(booking.customer.totalMinor,booking.customer.currency)}<small>customer paid</small></span>
      <span>${money(booking.provider.totalMinor,booking.provider.currency)}<small>provider cost</small></span>
      <span>${booking.estimatedProfitMinor == null ? "Not available" : money(booking.estimatedProfitMinor,booking.customer.currency)}<small>estimated profit</small></span>
      <span>${escapeHtml(booking.pricingConfig.version == null ? "Legacy/env" : `Pricing v${booking.pricingConfig.version}`)}<small>${escapeHtml(booking.bookingReference || "No reference")}</small></span></button>`).join("");
    container.querySelectorAll("[data-booking-id]").forEach((button) => button.addEventListener("click", () => openBooking(button.dataset.bookingId)));
  } catch (error) { container.innerHTML = empty("Bookings unavailable", error.message); }
}

async function openBooking(id) {
  try {
    const data = await api(`/flights/bookings/${encodeURIComponent(id)}`); const booking = data.booking; const e = booking.economics;
    const fields = [
      ["Status",booking.status],["Customer paid",money(booking.customer.totalMinor,booking.customer.currency)],
      ["Provider cost",money(booking.provider.totalMinor,booking.provider.currency)],["FX rate",e.customer_fx_rate || "Not available"],
      ["FX protection",money(e.customer_fx_protection_minor,booking.customer.currency)],["Zippi markup",money(e.customer_zippi_markup_minor,booking.customer.currency)],
      ["Booking fee",money(e.customer_zippi_fee_minor,booking.customer.currency)],["Processing allowance",money(e.customer_payment_processing_allowance_minor,booking.customer.currency)],
      ["Estimated processing",money(e.customer_estimated_processing_minor,booking.customer.currency)],["Minimum-margin adjustment",money(e.customer_min_margin_top_up_minor,booking.customer.currency)],
      ["Rounding adjustment",money(e.customer_rounding_adjustment_minor,booking.customer.currency)],["Estimated Zippi profit",money(e.customer_estimated_gross_margin_minor,booking.customer.currency)],
      ["Pricing source",booking.pricingConfig.source],["Pricing config version",booking.pricingConfig.version == null ? "Legacy / environment" : `Version ${booking.pricingConfig.version}`],
      ["Booking reference",booking.bookingReference || "Not assigned"],["Session ID",booking.id],
    ];
    document.getElementById("booking-detail").innerHTML = `<div class="detail-content"><p class="eyebrow">Persisted pricing snapshot</p><h2>${escapeHtml(booking.route)}</h2><div class="detail-grid">${fields.map(([label,value]) => `<div class="detail-item"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong></div>`).join("")}</div></div>`;
    document.getElementById("booking-dialog").showModal();
  } catch (error) { toast(error.message); }
}

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll("a[data-route]").forEach((link) => link.addEventListener("click", (event) => { event.preventDefault(); navigate(link.dataset.route); }));
  window.addEventListener("popstate", () => navigate(routeFromPath(location.pathname), false));
  document.getElementById("flight-pricing-form").addEventListener("input", schedulePreview);
  document.getElementById("provider-amount").addEventListener("input", schedulePreview);
  document.getElementById("provider-currency").addEventListener("change", schedulePreview);
  document.getElementById("customer-currency").addEventListener("change", schedulePreview);
  document.getElementById("reset-flight-config").addEventListener("click", () => { writeConfig(state.config); schedulePreview(); });
  document.getElementById("save-flight-draft").addEventListener("click", saveDraft);
  document.getElementById("review-active-draft").addEventListener("click", () => { if (state.draft) reviewPricingAction("activate", Number(state.draft.version)); });
  document.querySelector(".dialog-close").addEventListener("click", () => document.getElementById("booking-dialog").close());
  document.querySelector(".pricing-dialog-close").addEventListener("click", () => document.getElementById("pricing-action-dialog").close());
  try { await loadConfig(); } catch (error) { toast(error.message); }
  navigate(routeFromPath(location.pathname), false);
});
