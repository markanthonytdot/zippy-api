"use strict";

// The existing admin cookie authenticates every read/write. Nothing is stored in browser storage.
const partnerState = { organizations: [], people: [], mode: "add", selected: null, action: null };
const byId = (id) => document.getElementById(id);
const featureLabels = { flights: "Flights", hotels: "Hotels", combinedTrip: "Combined Trip", checkout: "Checkout" };
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function escapePartnerText(value) {
  const node = document.createElement("span");
  node.textContent = String(value ?? "");
  return node.innerHTML;
}

function partnerDate(value) {
  const date = value ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? dateFormat.format(date) : "—";
}

async function partnerApi(path = "", body) {
  const response = await fetch(`/admin/api/partner-access${path}`, {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (response.status === 401) {
    window.location.assign("/admin/login");
    throw new Error("Your admin session ended. Please sign in again.");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) {
    const messages = {
      400: "Check the email, organization, dates, and selected access. Then try again.",
      403: "This action could not be authorized. Reload this page and try again.",
      404: "This invitation is no longer available. Refresh the list.",
      409: "This email already has an invitation. Edit the existing person instead.",
      429: "Please wait a moment before trying again.",
      503: "Partner Access is not configured yet. Check the local setup instructions.",
    };
    throw new Error(messages[response.status] || "Partner Access could not be updated. Please try again.");
  }
  return payload;
}

function partnerMessage(message) {
  byId("partner-message").textContent = message;
  byId("partner-message").hidden = !message;
}

function renderPartners() {
  byId("active-count").textContent = partnerState.people.filter((p) => p.access === "active" && p.activatedAt).length;
  byId("pending-count").textContent = partnerState.people.filter((p) => !p.activatedAt && ["active", "scheduled"].includes(p.access)).length;
  byId("organization-count").textContent = partnerState.organizations.length;
  const selected = byId("organization-filter").value;
  const people = partnerState.people.filter((person) => !selected || person.organizationId === selected);
  byId("people-list").innerHTML = people.length ? people.map((person) => {
    const access = person.access || "unavailable";
    const status = access === "active" && !person.activatedAt ? "pending" : access;
    const labels = { active: "Active", pending: "Invited", scheduled: "Scheduled", expired: "Expired", revoked: "Revoked", unavailable: "Unavailable", none: "Unavailable" };
    const safeStatus = Object.hasOwn(labels, status) ? status : "unavailable";
    const features = Object.entries(featureLabels).filter(([key]) => person.features?.[key] === true).map(([, label]) => label);
    const platforms = (person.platforms || []).map((platform) => platform === "ios" ? "iOS" : platform === "android" ? "Android" : platform);
    return `<tr data-person-id="${escapePartnerText(person.id)}">
      <td><strong>${escapePartnerText(person.email)}</strong><small>${escapePartnerText(person.organization)}</small></td>
      <td><span class="partner-status ${safeStatus}">${labels[safeStatus]}</span><small>Starts ${escapePartnerText(partnerDate(person.startsAt))}</small></td>
      <td>${escapePartnerText(partnerDate(person.expiresAt))}</td>
      <td>${escapePartnerText(features.join(" · ") || "No features")}<small>${escapePartnerText(platforms.join(" · ") || "No platforms")}</small></td>
      <td>${person.activatedAt ? `Activated ${escapePartnerText(partnerDate(person.activatedAt))}` : "Not activated"}<small>Last check ${escapePartnerText(partnerDate(person.lastCheckedAt))}</small></td>
      <td><div class="partner-row-actions"><button type="button" class="text-button" data-action="extend">Extend</button><button type="button" class="text-button" data-action="edit">Edit access</button><button type="button" class="text-button" data-action="${person.revokedAt || person.status === "disabled" ? "restore" : "revoke"}">${person.revokedAt || person.status === "disabled" ? "Restore" : "Revoke"}</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="6" class="partner-empty">No invitations yet. Add an organization, then approve a person’s work email.</td></tr>';
}

async function loadPartners() {
  byId("refresh").disabled = true;
  try {
    const data = await partnerApi();
    partnerState.organizations = data.organizations || [];
    partnerState.people = data.people || [];
    const filter = byId("organization-filter");
    const previous = filter.value;
    filter.innerHTML = '<option value="">All organizations</option>' + partnerState.organizations.map((org) => `<option value="${escapePartnerText(org.id)}">${escapePartnerText(org.name)}</option>`).join("");
    filter.value = partnerState.organizations.some((org) => org.id === previous) ? previous : "";
    renderPartners();
    return true;
  } catch (error) {
    partnerMessage(error.message);
    return false;
  } finally {
    byId("refresh").disabled = false;
  }
}

function durationChanged() {
  const form = byId("person-form");
  const custom = form.elements.duration.value === "custom";
  byId("custom-expiry-label").hidden = !custom;
  form.elements.expiresAt.required = custom && partnerState.mode !== "edit";
}

function openPerson(mode, person = null) {
  partnerState.mode = mode;
  partnerState.selected = person;
  const form = byId("person-form");
  form.reset();
  byId("person-error").textContent = "";
  const adding = mode === "add";
  const extending = mode === "extend";
  byId("person-title").textContent = adding ? "Add person" : extending ? "Extend preview" : "Edit access";
  byId("save-person").textContent = adding ? "Add person" : extending ? "Extend preview" : "Save access";
  byId("person-copy").textContent = adding
    ? "Approve their work email. They receive a code only when they request one in the app."
    : extending ? `${person.email} · Add time from the current expiry, or today if it has passed. Revoked access stays revoked until you restore it.` : person.email;
  byId("person-identity").hidden = !adding;
  byId("start-label").hidden = !adding;
  byId("duration-fields").hidden = mode === "edit";
  byId("entitlement-fields").hidden = extending;
  form.elements.email.required = adding;
  form.elements.organizationId.required = adding;
  form.elements.organizationId.innerHTML = '<option value="">Select organization</option>' + partnerState.organizations.filter((org) => org.status === "active").map((org) => `<option value="${escapePartnerText(org.id)}">${escapePartnerText(org.name)}</option>`).join("");
  if (adding) form.elements.organizationId.value = byId("organization-filter").value;
  for (const platform of ["ios", "android"]) form.elements[platform].checked = person ? person.platforms.includes(platform) : true;
  for (const key of Object.keys(featureLabels)) form.elements[key].checked = person ? person.features[key] === true : key !== "checkout";
  durationChanged();
  byId("person-dialog").showModal();
}

async function durationBody(form) {
  if (form.elements.duration.value === "1") {
    // Use the existing custom-expiry contract; the server retains all validation.
    const { serverTime } = await partnerApi();
    const now = new Date(serverTime).getTime();
    const start = partnerState.mode === "extend"
      ? Math.max(now, new Date(partnerState.selected.expiresAt).getTime())
      : form.elements.startsAt.value ? new Date(form.elements.startsAt.value).getTime() : now;
    if (!Number.isFinite(now) || !Number.isFinite(start)) throw new Error("Refresh the list and choose a valid start time.");
    return { expiresAt: new Date(start + 86400000).toISOString() };
  }
  if (form.elements.duration.value !== "custom") return { durationDays: Number(form.elements.duration.value) };
  const date = new Date(form.elements.expiresAt.value);
  if (!Number.isFinite(date.getTime())) throw new Error("Choose a valid custom expiry.");
  return { expiresAt: date.toISOString() };
}

async function withPartnerSubmission(form, errorId, action) {
  const button = form.querySelector('button[type="submit"]');
  if (button.disabled) return;
  button.disabled = true;
  byId(errorId).textContent = "";
  try { await action(); } catch (error) { byId(errorId).textContent = error.message; }
  finally { button.disabled = false; }
}

document.addEventListener("DOMContentLoaded", () => {
  byId("refresh").addEventListener("click", () => { partnerMessage(""); loadPartners(); });
  byId("organization-filter").addEventListener("change", renderPartners);
  byId("add-person").addEventListener("click", () => openPerson("add"));
  byId("add-organization").addEventListener("click", () => {
    byId("organization-form").reset(); byId("organization-error").textContent = ""; byId("organization-dialog").showModal();
  });
  document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
  byId("person-form").elements.duration.addEventListener("change", durationChanged);
  byId("people-list").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const person = partnerState.people.find((p) => p.id === button.closest("tr").dataset.personId);
    if (!person) return;
    const action = button.dataset.action;
    if (["edit", "extend"].includes(action)) return openPerson(action, person);
    partnerState.selected = person; partnerState.action = action;
    byId("action-title").textContent = action === "revoke" ? "Revoke access" : "Restore access";
    byId("confirm-action").textContent = byId("action-title").textContent;
    byId("action-copy").textContent = action === "revoke"
      ? `${person.email} will lose preview access on their next check.`
      : `${person.email} can use their existing verified session again if the preview has not expired. Extend the expiry separately if needed.`;
    byId("action-error").textContent = ""; byId("action-dialog").showModal();
  });
  byId("person-form").addEventListener("submit", (event) => {
    event.preventDefault(); const form = event.currentTarget;
    withPartnerSubmission(form, "person-error", async () => {
      const mode = partnerState.mode;
      let body = mode === "edit" ? {} : await durationBody(form);
      if (mode !== "extend") {
        body.platforms = ["ios", "android"].filter((p) => form.elements[p].checked);
        if (!body.platforms.length) throw new Error("Choose at least one platform.");
        body.features = Object.fromEntries(Object.keys(featureLabels).map((key) => [key, form.elements[key].checked]));
      }
      if (mode === "add") {
        body.email = form.elements.email.value.trim(); body.organizationId = form.elements.organizationId.value;
        if (form.elements.startsAt.value) body.startsAt = new Date(form.elements.startsAt.value).toISOString();
      }
      const path = mode === "add" ? "/people" : `/people/${encodeURIComponent(partnerState.selected.id)}/${mode === "edit" ? "update" : "extend"}`;
      await partnerApi(path, body);
      byId("person-dialog").close();
      partnerMessage(mode === "add" ? "Invitation saved. No email has been sent." : "Preview access updated.");
      await loadPartners();
    });
  });
  byId("organization-form").addEventListener("submit", (event) => {
    event.preventDefault(); const form = event.currentTarget;
    withPartnerSubmission(form, "organization-error", async () => {
      await partnerApi("/organizations", { name: form.elements.name.value.trim(), allowedEmailDomains: form.elements.domains.value.split(",").map((v) => v.trim().toLowerCase()).filter(Boolean) });
      byId("organization-dialog").close(); partnerMessage("Organization added."); await loadPartners();
    });
  });
  byId("action-form").addEventListener("submit", (event) => {
    event.preventDefault(); const form = event.currentTarget;
    withPartnerSubmission(form, "action-error", async () => {
      const revoke = partnerState.action === "revoke";
      await partnerApi(`/people/${encodeURIComponent(partnerState.selected.id)}/${revoke ? "revoke" : "update"}`, revoke ? {} : { status: "active" });
      byId("action-dialog").close(); partnerMessage(revoke ? "Preview access revoked." : "Preview access restored. The existing expiry still applies."); await loadPartners();
    });
  });
  loadPartners();
});
