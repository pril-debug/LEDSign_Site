document.querySelectorAll('.ssid').forEach(button => button.addEventListener('click', () => {
  const field = document.getElementById('ssid'); field.value = button.dataset.ssid; field.focus();
}));
document.querySelectorAll('form').forEach(form => form.addEventListener('submit', event => {
  if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) { event.preventDefault(); return; }
  const button = form.querySelector('button[type="submit"], button:not([type])');
  if (button) { button.disabled = true; button.textContent = 'Working…'; }
  form.setAttribute('aria-busy', 'true');
}));
