(() => {
  const form = document.getElementById('tester-invite-form');
  if (!form) return;
  const radio = form.querySelector('input[value="android"]');
  const emailLabel = document.getElementById('tester-email-label');
  const helper = document.getElementById('tester-google-email-help');
  const message = document.getElementById('tester-invite-message');
  const submit = document.getElementById('tester-invite-submit');
  const panel = document.getElementById('android-tester-panel');
  const rows = document.getElementById('android-tester-rows');
  const iosSections = document.querySelectorAll('.partner-summary, .partner-list-panel');
  const productionOnly = document.body.dataset.testerAuthority === 'production';
  let config = { enabled: false }; let invitations = []; let busy = false;
  let androidErrorText = null;
  const errors = {
    play_eligibility_unconfirmed: 'Add this email to a Play Console tester list, then confirm eligibility here before sending.',
    preview_access_inactive: 'Zippi preview access is inactive. No invitation was sent.',
    invitation_in_progress: 'Another action is running. Refresh to check its result.',
    invitation_cooldown: 'Please allow five minutes between instruction-email attempts or resends.',
    mail_unavailable: 'Email delivery was not confirmed. Access and Play eligibility are preserved; retry instructions later.',
    mail_delivery_check_required: 'Delivery is uncertain. Check the email provider before attempting another send.',
    rate_limited: 'Too many actions. Please try again later.',
    invalid_email: 'Enter a valid Google Play email address.',
    invalid_duration: 'Enter a whole number of days from 1 to 90.',
    expiry_changed: 'Access expiry changed since this page loaded. Refresh and review it before extending.',
    invalid_expiry: 'Refresh and choose a valid access duration.',
    admin_auth_required: 'Your admin session ended. Sign in again.',
  };
  const explain = value => errors[value] || 'Production tester access could not be confirmed. Refresh and try again.';
  function showError(text) { androidErrorText = text; message.textContent = text; }
  const node = (tag, text, className) => { const n = document.createElement(tag); n.textContent = text; if (className) n.className = className; return n; };
  function confirmAction(email, description) {
    return new Promise(resolve => {
      const dialog = node('dialog', '', 'android-tester-confirm');
      dialog.setAttribute('aria-label', 'Confirm tester action');
      dialog.append(node('strong', email), node('p', description));
      const buttons = node('div', '', 'tester-row-actions');
      const cancel = node('button', 'Cancel'); const confirm = node('button', 'Confirm');
      function finish(value) { dialog.close(); dialog.remove(); resolve(value); }
      cancel.addEventListener('click', () => finish(false)); confirm.addEventListener('click', () => finish(true));
      dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
      buttons.append(cancel, confirm); dialog.append(buttons); document.body.append(dialog); dialog.showModal(); cancel.focus();
    });
  }
  async function api(body) {
    const response = await fetch('/admin/api/android-testers', { method: body ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store',
      ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
    const result = await response.json();
    if (!response.ok) throw new Error(explain(result.error));
    return result;
  }
  function render() {
    const android = form.elements.platform.value === 'android';
    panel.hidden = !android; helper.hidden = !android;
    emailLabel.textContent = android ? 'Google Play email' : 'Email';
    form.querySelector('.tester-organization').hidden = android;
    for (const section of iosSections) section.hidden = android;
    if (!android) return;
    submit.textContent = 'Prepare Android invitation';
    submit.disabled = busy || !config.enabled || !config.policyConfigured;
    document.getElementById('tester-policy').textContent = config.enabled
      ? 'Android preview access is managed in production. The selected duration applies to new testers only. Existing expiry is preserved.' : 'Production Android tester setup is pending.';
    document.getElementById('tester-readiness').textContent = 'Prepare access → add the email in Play Console → confirm eligibility → send invitation. Google Play enrollment is manual.';
    rows.replaceChildren();
    if (!invitations.length) rows.append(node('p', 'No production Android testers recorded.'));
    for (const item of invitations) {
      const card = node('article', '', 'android-tester-card');
      card.append(node('strong', item.email));
      card.append(node('p', `Zippi access: ${{ active: 'Active', disabled: 'Disabled', revoked: 'Revoked', expired: 'Expired', scheduled: 'Scheduled', unavailable: 'Unavailable' }[item.access] || 'Unavailable'}`));
      card.append(node('p', `Expires: ${testerAccessDuration.format(item.expiresAt)}`));
      card.append(node('p', `Play eligibility: ${{ confirmed: 'Confirmed', not_confirmed: 'Not confirmed', removed: 'Removed' }[item.playEligibility] || 'Not confirmed'}`));
      card.append(node('p', `Invitation email: ${{ not_sent: 'Not sent', sending: 'Sending / unconfirmed', sent: 'Sent (provider accepted)', failed: 'Failed / unconfirmed' }[item.emailStatus] || 'Not sent'}`));
      if (item.emailStatus === 'sent') card.append(node('p', "Invitation sent. If the tester doesn't see it within a few minutes, ask them to check Spam or Promotions."));
      if (item.error) card.append(node('p', explain(item.error), 'partner-error'));
      const controls = node('div', '', 'tester-row-actions');
      function action(label, name, disabled = false, confirmation) {
        const button = node('button', label, 'text-button'); button.type = 'button'; button.disabled = busy || disabled;
        button.addEventListener('click', async () => {
          if (confirmation && !await confirmAction(item.email, confirmation)) return;
          await operate({ action: name, platform: 'android', id: item.id, ...(confirmation ? { confirm: true } : {}) });
        });
        controls.append(button);
      }
      if (item.playEligibility !== 'confirmed') action('Confirm Play eligibility', 'confirm', item.access !== 'active', 'Confirm that you manually added this exact Google Play email to a tester list selected for Zippi Internal Testing. This does not send an email.');
      if (item.playEligibility === 'confirmed') action('Mark not confirmed', 'unconfirm', false, 'Mark Play eligibility as unconfirmed? This changes only the dashboard record.');
      if (item.playEligibility !== 'removed') action('Mark removed from Play', 'removed', false, 'Confirm that you manually removed this email from Play eligibility. This does not revoke Zippi access or uninstall the app.');
      const cooling = item.retryAfter && Date.parse(item.retryAfter) > Date.now();
      action(item.emailStatus === 'sent' ? 'Resend instructions' : item.emailStatus === 'not_sent' ? 'Send Android invitation' : 'Retry instructions',
        item.emailStatus === 'sent' ? 'resend' : item.emailStatus === 'not_sent' ? 'send' : 'retry',
        item.access !== 'active' || item.playEligibility !== 'confirmed' || cooling || !config.emailConfigured);
      if (item.access === 'active' || item.access === 'scheduled') {
        action('Revoke Zippi access', 'revoke', false, 'Revoke production Zippi preview access? Play eligibility and the installed app remain unchanged.');
        action('Disable Zippi access', 'disable', false, 'Disable production Zippi preview access? Play eligibility and the installed app remain unchanged.');
      }
      const extend = node('button', 'Extend access', 'text-button'); extend.type = 'button'; extend.disabled = busy;
      extend.addEventListener('click', async () => {
        const selection = await testerAccessDuration.extend(item);
        if (selection) await operate({ action: 'extend', platform: 'android', id: item.id, ...selection });
      });
      controls.append(extend);
      card.append(controls); rows.append(card);
    }
  }
  async function load() {
    const result = await api(); config = result.config; invitations = result.invitations || [];
    form.dataset.androidProductionEnabled = config.enabled ? 'true' : '';
    radio.disabled = !config.enabled;
    document.getElementById('tester-android-status').textContent = config.enabled ? '(production)' : '(setup pending)';
    render();
  }
  async function operate(body) {
    if (busy) return; busy = true; androidErrorText = null; render(); message.textContent = 'Updating production Android tester access…';
    try {
      const result = await api(body);
      message.textContent = result.invitation.error ? explain(result.invitation.error) : body.action === 'prepare'
        ? `Access prepared. Existing expiry is preserved for returning testers. Expires: ${testerAccessDuration.format(result.invitation.expiresAt)}. No email sent.`
        : body.action === 'confirm' ? 'Manual Play eligibility confirmed. No email sent.'
        : 'Action recorded. Zippi access, Play eligibility and email delivery are shown separately below.';
    } catch (error) { showError(error.message); }
    finally { busy = false; try { await load(); } catch { showError(message.textContent + ' Refresh to check the recorded outcome.'); } render(); }
  }
  async function refresh() {
    if (busy) return;
    const previousError = androidErrorText;
    try {
      await load();
      // Clear only a recovered Android error, not an iOS message or a newer action.
      if (!busy && form.elements.platform.value === 'android' && previousError !== null
        && androidErrorText === previousError && message.textContent === previousError) {
        androidErrorText = null; message.textContent = '';
      }
    } catch { if (form.elements.platform.value === 'android') showError(explain()); }
  }
  form.addEventListener('submit', event => {
    if (form.elements.platform.value !== 'android') return;
    event.preventDefault();
    const durationDays = testerAccessDuration.read(form);
    if (!submit.disabled && durationDays !== null) operate({ action: 'prepare', platform: 'android', email: form.elements.email.value, durationDays });
  });
  form.addEventListener('change', event => {
    if (event.target.name === 'platform' && !busy) message.textContent = '';
    if (form.elements.platform.value === 'ios') submit.textContent = 'Invite to Zippi'; render();
  });
  document.addEventListener('android-tester-render', render);
  document.getElementById('tester-refresh').addEventListener('click', refresh);
  if (productionOnly) radio.checked = true;
  load().catch(() => { if (productionOnly) showError(explain()); render(); });
})();
