document.querySelectorAll('.ssid').forEach(button => button.addEventListener('click', () => {
  const field = document.getElementById('ssid'); field.value = button.dataset.ssid;
  const security = field.form.querySelector('select[name="security"]');
  if (security && button.dataset.security) security.value = button.dataset.security;
  field.focus();
}));
const modal = document.getElementById('confirmation-modal');
let pending = null;
const approved = new WeakSet();
modal.addEventListener('close', () => {
  if (!pending) return;
  const { form, trigger } = pending;
  pending = null;
  if (modal.returnValue === 'confirm') {
    const confirmation = form.querySelector('input[type="hidden"][name="confirm"]');
    if (confirmation) confirmation.value = 'yes';
    approved.add(form);
    form.requestSubmit();
  } else if (trigger) {
    trigger.focus();
  }
});
modal.addEventListener('cancel', () => { modal.returnValue = 'cancel'; });
document.querySelectorAll('form:not([method="dialog"])').forEach(form => form.addEventListener('submit', event => {
  const hostname = form.querySelector('input[name="hostname"]');
  if (hostname) hostname.value = hostname.value.trim().toLowerCase();
  if (form.dataset.confirm && !approved.has(form)) {
    event.preventDefault();
    if (pending) return;
    pending = { form, trigger: document.activeElement };
    document.getElementById('confirmation-title').textContent = form.dataset.confirmTitle || 'Confirm change';
    document.getElementById('confirmation-description').textContent = hostname
      ? `Save the device name as “${hostname.value}”?` : form.dataset.confirm;
    modal.returnValue = '';
    modal.showModal();
    return;
  }
  approved.delete(form);
  const button = form.querySelector('button[type="submit"], button:not([type])');
  if (button) { button.disabled = true; button.textContent = form.dataset.busy || (form.method.toLowerCase() === 'get' ? 'Searching…' : 'Saving…'); }
  form.setAttribute('aria-busy', 'true');
}));
document.querySelectorAll('select[name="mode"]').forEach(select => {
  const fields = select.form.querySelector('.static-fields');
  if (!fields) return;
  const update = () => {
    const inactive = select.value === 'dhcp';
    fields.dataset.inactive = String(inactive);
    fields.querySelectorAll('input').forEach(input => { input.disabled = inactive; input.required = !inactive; });
  };
  select.addEventListener('change', update); update();
});
document.querySelectorAll('time[data-local-time]').forEach(time => {
  const date = new Date(time.dateTime);
  if (!Number.isNaN(date.getTime())) {
    time.textContent = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(date);
    time.title = 'Your local time';
  }
});
