document.querySelectorAll('.ssid').forEach(button => button.addEventListener('click', () => {
  const field = document.getElementById('ssid'); field.value = button.dataset.ssid; field.focus();
}));
document.querySelectorAll('form').forEach(form => form.addEventListener('submit', event => {
  if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) { event.preventDefault(); return; }
  const button = form.querySelector('button[type="submit"], button:not([type])');
  if (button) { button.disabled = true; button.textContent = 'Saving…'; }
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
