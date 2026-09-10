(() => {
  const form = document.getElementById("tester-invite-form");
  if (!form) return;
  const message = document.getElementById("tester-invite-message");
  const submit = document.getElementById("tester-invite-submit");
  let config; let pending = false;
  const errors = {
    tester_invitations_disabled: "Tester invitations are awaiting setup.", tester_policy_not_configured: "Set the default tester organization in the staging environment.",
    apple_not_configured: "Apple API access and a tester key are required.", apple_no_testable_build: "The configured TestFlight group has no build available for external testing.",
    android_preview_build_unverified: "The intended Android preview build is not yet verified on Google Play.",
    apple_authorization_failed: "Apple rejected the API permissions. Check the server key and role.", apple_group_mismatch: "The configured group must be an external group for Zippi.",
    apple_rate_limited: "Apple is rate limiting requests. Try again later.", apple_unavailable: "Apple could not confirm the invitation. Retry later.",
    apple_tester_revoked: "This tester has stopped testing or lost Apple access. Review their TestFlight status.",
    platform_unavailable: "Platform access could not be confirmed. No welcome email was sent. Retry later.",
    mail_unavailable: "The welcome email was not confirmed. Retry instructions; platform access is preserved.",
    mail_delivery_check_required: "Delivery is uncertain and the safe retry window has elapsed. Check Resend before taking further action.",
    preview_access_inactive: "Preview access is inactive. Use Extend or Restore in Partner Access before retrying.",
    invitation_cooldown: "Please allow five minutes between attempts or resends.", invitation_in_progress: "An invitation is already running. Refresh the list shortly.",
    invalid_email: "Enter a valid email address.", invalid_platform: "Choose iOS or Android.", rate_limited: "Invitation limit reached. Try again later.",
    email_domain_not_allowed: "This email domain is not allowed by the tester organization.", admin_auth_required: "Your admin session has expired. Sign in again.",
  };
  const labels = { NOT_INVITED: "Awaiting Apple invitation", INVITED: "Invited", ACCEPTED: "Accepted", INSTALLED: "Installed", REVOKED: "Revoked", OPT_IN_REQUIRED: "Opt-in required" };
  const explain = code => errors[code] || "The operation was not confirmed. Refresh or retry later.";
  const date = value => value ? new Date(value).toLocaleString() : "—";
  function node(tag, text, className) { const element = document.createElement(tag); element.textContent = text; if (className) element.className = className; return element; }
  async function api(path = "", body) {
    const response = await fetch(`/admin/api/tester-invitations${path}`, { method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
      ...(body ? { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}) });
    const result = await response.json();
    if (!response.ok) throw new Error(explain(result.error));
    return result;
  }
  function readiness() {
    const platform = form.elements.platform.value;
    const ready = config?.enabled && config.policyConfigured && config.emailConfigured && config.platforms[platform];
    submit.disabled = pending || !ready;
    document.getElementById("tester-policy").textContent = config?.policyConfigured
      ? `New previews last ${config.durationDays} days with Flights, Hotels and Combined Trip on, Checkout off. Existing access settings are preserved.` : "Default preview policy needs setup.";
    document.getElementById("tester-readiness").textContent = !config?.enabled ? errors.tester_invitations_disabled
      : !config.platforms[platform] ? explain(platform === "ios" ? "apple_not_configured" : "android_preview_build_unverified")
      : !config.emailConfigured ? "Welcome email delivery needs setup." : platform === "android" ? "Testers must opt in through Google Play themselves." : "Apple will check group and build readiness before inviting anyone.";
  }
  function render(rows) {
    const list = document.getElementById("tester-invitation-list"); list.replaceChildren();
    if (!rows.length) { const row = node("tr", ""); const cell = node("td", "No tester invitations yet."); cell.colSpan = 6; row.append(cell); list.append(row); }
    for (const item of rows) {
      const row = node("tr", ""); const email = node("td", item.email); email.append(node("small", item.platform === "ios" ? "iOS" : "Android", "tester-secondary"));
      const platform = node("td", item.platformStatus === "failed" ? "Failed" : labels[item.providerState] || "Pending");
      if (item.error) platform.append(node("p", explain(item.error), "tester-error"));
      const emailState = node("td", { sent: "Sent (provider accepted)", failed: "Failed / unconfirmed", sending: "Sending / unconfirmed", not_sent: "Not sent" }[item.emailStatus] || "Not sent");
      const activity = node("td", `Invited: ${date(item.invitedAt)}`); activity.append(node("small", `Last attempt: ${date(item.lastAttemptAt)}`, "tester-secondary"), node("small", `Updated: ${date(item.updatedAt)}`, "tester-secondary"));
      const actions = node("td", ""); const buttons = node("div", "", "tester-row-actions"); actions.append(buttons);
      function action(label, name) {
        const button = node("button", label, "text-button"); button.type = "button";
        button.disabled = pending || item.access !== "active" || new Date(item.retryAfter).getTime() > Date.now();
        button.addEventListener("click", () => operate(`/${item.id}/${name}`, {})); buttons.append(button);
      }
      if (item.error || item.platformStatus !== "confirmed" || item.emailStatus !== "sent") action("Retry", "retry");
      if (item.platformStatus === "confirmed") {
        action("Resend instructions", "resend");
        if (item.platform === "ios") { action("Refresh Apple status", "refresh"); if (["NOT_INVITED", "INVITED"].includes(item.providerState)) action("Resend TestFlight invite", "apple-resend"); }
      }
      row.append(email, node("td", item.access), platform, emailState, activity, actions); list.append(row);
    }
  }
  async function load() { const result = await api(); config = result.config; render(result.invitations); readiness(); }
  async function operate(path, body) {
    if (pending) return;
    pending = true; readiness();
    for (const button of document.querySelectorAll(".tester-row-actions button")) button.disabled = true;
    message.textContent = "Working on the invitation…";
    try {
      const result = await api(path, body);
      message.textContent = result.invitation.error ? explain(result.invitation.error) : `${result.invitation.email}: ${labels[result.invitation.providerState] || "Pending"}. Welcome email: ${result.invitation.emailStatus}.`;
      document.dispatchEvent(new Event("tester-invitation-updated"));
    } catch (error) { message.textContent = error.message; }
    finally { pending = false; try { await load(); } catch { message.textContent += " Refresh the list to check the recorded outcome."; } readiness(); }
  }
  form.addEventListener("submit", event => { event.preventDefault(); if (!submit.disabled) operate("", { email: form.elements.email.value, platform: form.elements.platform.value }); });
  form.addEventListener("change", readiness);
  document.getElementById("tester-refresh").addEventListener("click", () => load().catch(() => { message.textContent = "Couldn't refresh invitations."; }));
  load().catch(() => { message.textContent = "Tester invitations are unavailable. Existing Partner Access controls remain available below."; });
})();
