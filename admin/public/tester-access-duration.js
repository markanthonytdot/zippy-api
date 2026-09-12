// Shared duration presentation; the server independently validates every write.
const testerAccessDuration = (() => {
  const days = [1, 3, 7, 14, 30];
  const errorText = 'Enter a whole number of days from 1 to 90.';
  function parse(selected, custom) {
    const raw = String(selected === 'custom' ? custom ?? '' : selected).trim();
    const value = /^\d+$/.test(raw) ? Number(raw) : NaN;
    return Number.isInteger(value) && value >= 1 && value <= 90 ? value : null;
  }
  function bind(select, input, label, error) {
    function read() {
      const value = parse(select.value, input.value);
      error.textContent = value === null ? errorText : '';
      input.setAttribute('aria-invalid', String(value === null && select.value === 'custom'));
      return value;
    }
    function sync() {
      const custom = select.value === 'custom';
      label.hidden = !custom; input.disabled = !custom; input.required = custom;
      error.textContent = ''; input.setAttribute('aria-invalid', 'false');
    }
    select.addEventListener('change', sync);
    input.addEventListener('input', read); input.addEventListener('invalid', read);
    sync(); return { read, sync };
  }
  const form = document.getElementById('tester-invite-form');
  const invitation = form && bind(form.elements.durationDays, form.elements.customDurationDays,
    document.getElementById('tester-custom-days-label'), document.getElementById('tester-duration-error'));
  const format = value => value && Number.isFinite(Date.parse(value))
    ? new Date(value).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric',
      hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }) : 'Not available';
  function extend(item) {
    return new Promise(resolve => {
      const make = (tag, text) => { const n = document.createElement(tag); n.textContent = text; return n; };
      const dialog = make('dialog', ''); dialog.className = 'android-tester-confirm';
      dialog.setAttribute('aria-label', 'Extend Zippi access');
      const select = make('select', ''); select.id = 'tester-extension-days';
      for (const count of days) { const option = make('option', `${count} ${count === 1 ? 'day' : 'days'}`); option.value = String(count); select.append(option); }
      const custom = make('option', 'Custom'); custom.value = 'custom'; select.append(custom); select.value = '7';
      const label = make('label', 'Add access time'); label.append(select);
      const input = make('input', ''); input.type = 'number'; input.min = '1'; input.max = '90'; input.step = '1';
      input.setAttribute('aria-describedby', 'tester-extension-error');
      const customLabel = make('label', 'Number of days'); customLabel.append(input);
      const error = make('p', ''); error.id = 'tester-extension-error'; error.className = 'tester-error'; error.setAttribute('role', 'alert');
      const control = bind(select, input, customLabel, error);
      const buttons = make('div', ''); buttons.className = 'tester-row-actions';
      const cancel = make('button', 'Cancel'), confirm = make('button', 'Extend access');
      cancel.type = confirm.type = 'button';
      const finish = value => { dialog.close(); dialog.remove(); resolve(value); };
      cancel.addEventListener('click', () => finish(null));
      confirm.addEventListener('click', () => {
        const durationDays = control.read();
        if (durationDays !== null) finish({ durationDays, expectedExpiresAt: item.expiresAt, confirm: true });
        else input.focus();
      });
      dialog.addEventListener('cancel', event => { event.preventDefault(); finish(null); });
      buttons.append(cancel, confirm);
      dialog.append(make('strong', item.email), make('p', `Current expiry: ${format(item.expiresAt)}`),
        make('p', 'Adds time from the current expiry, or now if it has expired. Revoked or disabled access stays blocked. Google Play membership and invitation email stay unchanged.'), label, customLabel, error, buttons);
      document.body.append(dialog); dialog.showModal(); cancel.focus();
    });
  }
  return { read: () => invitation.read(), bind, parse, errorText, format, extend };
})();
