"use strict";

// The existing admin cookie authenticates every read/write. Nothing is stored in browser storage.
const partnerState = { organizations: [], people: [], mode: "edit", selected: null, action: null };
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
    const deletionErrors = { delete_confirmation_required: "Confirm the complete person deletion.", delete_target_changed: "This person's records changed. Cancel, refresh and confirm the updated person.", invitation_in_progress: "An invitation is in progress. Wait for it to finish, then try again." };
    throw new Error((payload.error === "expiry_changed" ? "Expiry changed. Refresh and review it before extending." : null) || deletionErrors[payload.error] || messages[response.status] || "Partner Access could not be updated. Please try again.");
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
  const people = partnerState.people.filter((person) => !selected || (selected === "unassigned" ? !person.organizationId : person.organizationId === selected));
  byId("people-list").innerHTML = people.length ? people.map((person) => {
    const access = person.access || "unavailable";
    const status = person.status === "disabled" ? "disabled" : access;
    const labels = { active: "Active", disabled: "Disabled", pending: "Invited", scheduled: "Scheduled", expired: "Expired", revoked: "Revoked", unavailable: "Unavailable", none: "Unavailable" };
    const safeStatus = Object.hasOwn(labels, status) ? status : "unavailable";
    const features = Object.entries(featureLabels).filter(([key]) => person.features?.[key] === true).map(([, label]) => label);
    const platforms = (person.platforms || []).map((platform) => platform === "ios" ? "iOS" : platform === "android" ? "Android" : platform);
    return `<tr data-person-id="${escapePartnerText(person.id)}">
      <td><strong>${escapePartnerText(person.email)}</strong><small>${escapePartnerText(person.organization)}</small></td>
      <td><span class="partner-status ${safeStatus}">${labels[safeStatus]}</span><small>Starts ${escapePartnerText(partnerDate(person.startsAt))}</small></td>
      <td>${escapePartnerText(partnerDate(person.expiresAt))}</td>
      <td>${escapePartnerText(features.join(" · ") || "No features")}<small>${escapePartnerText(platforms.join(" · ") || "No platforms")}</small></td>
      <td>${person.activatedAt ? `Activated ${escapePartnerText(partnerDate(person.activatedAt))}` : "Not activated"}<small>Last check ${escapePartnerText(partnerDate(person.lastCheckedAt))}</small></td>
      <td class="tester-person-status" data-email="${escapePartnerText(person.email)}" data-access="${escapePartnerText(access)}">Loading invitation status…</td>
      <td><div class="partner-row-actions"><button type="button" class="text-button" data-action="extend">Extend</button><button type="button" class="text-button" data-action="edit">Edit access</button><button type="button" class="text-button" data-action="${person.revokedAt || person.status === "disabled" ? "restore" : "revoke"}">${person.revokedAt || person.status === "disabled" ? "Restore" : "Revoke"}</button><button type="button" class="text-button partner-destructive" data-action="delete">Delete</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="partner-empty">No people in this organization. Use Invite to Zippi above to invite someone.</td></tr>';
  document.dispatchEvent(new Event("partner-people-rendered"));
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
    if (partnerState.people.some(person => !person.organizationId)) filter.add(new Option("No organization", "unassigned"));
    filter.value = [...filter.options].some(option => option.value === previous) ? previous : "";
    renderPartners();
    return true;
  } catch (error) {
    partnerMessage(error.message);
    return false;
  } finally {
    byId("refresh").disabled = false;
  }
}

let personDuration;
function durationChanged() {
  personDuration.sync();
  if (partnerState.mode === "edit") {
    const input = byId("person-form").elements.customDurationDays;
    input.disabled = true; input.required = false;
  }
}

function openPerson(mode, person = null) {
  partnerState.mode = mode;
  partnerState.selected = person;
  const form = byId("person-form");
  form.reset();
  byId("person-error").textContent = "";
  const extending = mode === "extend";
  byId("person-title").textContent = extending ? "Extend preview" : "Edit access";
  byId("save-person").textContent = extending ? "Extend preview" : "Save access";
  byId("person-copy").textContent = extending
    ? `${person.email} · Current expiry: ${partnerDate(person.expiresAt)}. Add time from that expiry, or now if it has passed. Revoked or disabled access stays blocked until explicitly restored.` : person.email;
  byId("duration-fields").hidden = mode === "edit";
  byId("entitlement-fields").hidden = extending;
  for (const platform of ["ios", "android"]) form.elements[platform].checked = person ? person.platforms.includes(platform) : true;
  for (const key of Object.keys(featureLabels)) form.elements[key].checked = person ? person.features[key] === true : key !== "checkout";
  durationChanged();
  byId("person-dialog").showModal();
}

async function durationBody(form) {
  const durationDays = personDuration.read();
  if (durationDays === null) throw new Error(testerAccessDuration.errorText);
  return { durationDays, expectedExpiresAt: partnerState.selected.expiresAt };
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
  const durationForm = byId("person-form");
  personDuration = testerAccessDuration.bind(durationForm.elements.duration, durationForm.elements.customDurationDays,
    byId("custom-expiry-label"), byId("person-error"));
  byId("refresh").addEventListener("click", () => { partnerMessage(""); loadPartners(); });
  byId("organization-filter").addEventListener("change", renderPartners);
  byId("add-organization").addEventListener("click", () => {
    byId("organization-form").reset(); byId("organization-error").textContent = ""; byId("organization-dialog").showModal();
  });
  document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
  byId("person-form").elements.duration.addEventListener("change", durationChanged);
  byId("people-list").addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const person = partnerState.people.find((p) => p.id === button.closest("tr").dataset.personId);
    if (!person) return;
    const action = button.dataset.action;
    if (["edit", "extend"].includes(action)) return openPerson(action, person);
    if (action === "delete") {
      button.disabled = true;
      try {
        const { target } = await partnerApi(`/people/${encodeURIComponent(person.id)}/deletion`);
        partnerState.deleteTarget = target;
        byId("delete-title").textContent = `Delete ${target.email}?`;
        byId("delete-copy").textContent = `Permanently remove this entire Zippi Partner Preview person across ALL listed platforms: ${target.platforms.map(p => p === "ios" ? "iOS" : "Android").join(" and ")}. This removes access, verification codes, invitations, welcome-email state and dashboard history. The organization and other people stay unchanged. A minimal security audit is retained. This does not remove or notify Apple TestFlight or Google testers.`;
        byId("delete-error").textContent = "";
        byId("delete-dialog").showModal();
      } catch (error) { partnerMessage(error.message); }
      finally { button.disabled = false; }
      return;
    }
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
      const path = `/people/${encodeURIComponent(partnerState.selected.id)}/${mode === "edit" ? "update" : "extend"}`;
      await partnerApi(path, body);
      byId("person-dialog").close();
      partnerMessage("Preview access updated.");
      await loadPartners();
    });
  });
  byId("organization-form").addEventListener("submit", (event) => {
    event.preventDefault(); const form = event.currentTarget;
    withPartnerSubmission(form, "organization-error", async () => {
      await partnerApi("/organizations", { name: form.elements.name.value.trim(), allowedEmailDomains: form.elements.domains.value.split(",").map((v) => v.trim().toLowerCase()).filter(Boolean) });
      byId("organization-dialog").close(); partnerMessage("Organization added."); await loadPartners();
      document.dispatchEvent(new Event("partner-organizations-updated"));
    });
  });
  byId("delete-form").addEventListener("submit", event => {
    event.preventDefault();
    withPartnerSubmission(event.currentTarget, "delete-error", async () => {
      const target = partnerState.deleteTarget;
      await partnerApi(`/people/${encodeURIComponent(target.personId)}/delete`, { ...target, confirm: true });
      byId("delete-dialog").close();
      partnerState.deleteTarget = null;
      partnerMessage("Person deleted from Zippi. Apple TestFlight and Google testers were not changed or notified.");
      await loadPartners();
      document.dispatchEvent(new Event("partner-person-deleted"));
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
  document.addEventListener("tester-invitation-updated", loadPartners);
});
