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
  if (form.id === 'display-settings') return;
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

const displayForm = document.getElementById('display-settings');
if (displayForm) {
  let layout = JSON.parse(displayForm.dataset.layout);
  const keys = ['width', 'height', 'columns', 'rows', 'sides'];
  const field = key => document.getElementById(`layout-${key}`);
  const dialog = document.getElementById('display-dialog');
  const cancel = document.getElementById('display-cancel');
  const ok = document.getElementById('display-ok');
  let nextAction = null;
  function showDialog(title, message, action = null) {
    document.getElementById('display-dialog-title').textContent = title;
    document.getElementById('display-dialog-message').textContent = message;
    nextAction = action; cancel.hidden = !action; ok.textContent = action ? 'Continue' : 'Close';
    dialog.showModal();
  }
  cancel.addEventListener('click', () => dialog.close());
  ok.addEventListener('click', () => { const action = nextAction; dialog.close(); if (action) action(); });
  displayForm.addEventListener('submit', event => event.preventDefault());
  function render() {
    const count = layout.columns * layout.rows;
    document.getElementById('layout-summary').textContent = `${count} panels per side · ${count * layout.sides} panels total · ${layout.width * layout.columns} × ${layout.height * layout.rows} pixels per side`;
    const root = document.getElementById('panel-mapping'); root.replaceChildren();
    for (let side = 1; side <= layout.sides; side++) {
      const title = document.createElement('h3'); title.textContent = `Side ${side}`; root.append(title);
      const grid = document.createElement('div'); grid.className = 'panel-map-grid';
      // CSS grid columns are selected from a fixed class list, compatible with CSP.
      grid.classList.add(`map-cols-${layout.columns}`);
      layout.panels.filter(p => p.side === side).sort((a,b) => a.y-b.y || a.x-b.x).forEach(p => {
        const tile = document.createElement('div'); tile.className = 'panel-map-tile';
        const position = document.createElement('strong'); position.textContent = `Row ${p.y+1}, column ${p.x+1}`; tile.append(position);
        const label = document.createElement('label'); label.textContent = 'Chain position';
        const input = document.createElement('input'); input.type = 'number'; input.min = '1'; input.max = String(count*layout.sides); input.value = p.chain; input.required = true;
        input.addEventListener('input', () => { p.chain = Number(input.value); }); label.append(input); tile.append(label);
        const rotation = document.createElement('label'); rotation.textContent = 'Orientation';
        const select = document.createElement('select');
        (layout.width === layout.height ? [0,90,180,270] : [0,180]).forEach(n => {
          const option = document.createElement('option'); option.value = n; option.textContent = `${n}°`; option.selected = p.rotation === n; select.append(option);
        });
        select.addEventListener('change', () => { p.rotation = Number(select.value); }); rotation.append(select); tile.append(rotation); grid.append(tile);
      }); root.append(grid);
    }
  }
  function generate() {
    keys.forEach(key => { layout[key] = Number(field(key).value); });
    const total = layout.columns * layout.rows * layout.sides;
    if (!displayForm.reportValidity()) return;
    if (total > 64) { showDialog('Check display size', 'Use no more than 64 panels on one output.'); return; }
    const pattern = document.getElementById('wiring-pattern').value;
    const corner = document.getElementById('wiring-corner').value;
    const vertical = pattern.startsWith('column'); const snake = pattern.includes('snake');
    const outer = vertical ? layout.columns : layout.rows, inner = vertical ? layout.rows : layout.columns;
    layout.panels = [];
    for (let side=1; side<=layout.sides; side++) for (let a=0; a<outer; a++) for (let b=0; b<inner; b++) {
      const offset = snake && a%2 ? inner-1-b : b;
      let x = vertical ? a : offset, y = vertical ? offset : a;
      if (corner.endsWith('r')) x = layout.columns-1-x;
      if (corner.startsWith('b')) y = layout.rows-1-y;
      layout.panels.push({chain:layout.panels.length+1, side, x, y, rotation:0});
    }
    render();
  }
  keys.forEach(key => field(key).addEventListener('change', generate));
  document.getElementById('panel-preset').addEventListener('change', event => {
    if (event.target.value === 'custom') return;
    const [w,h] = event.target.value.split(','); field('width').value=w; field('height').value=h; generate();
  });
  document.getElementById('generate-mapping').addEventListener('click', () => showDialog('Replace mapping?', 'Replace the current chain assignments with the selected wiring pattern?', generate));
  document.getElementById('initial-layout').addEventListener('click', () => showDialog('Use 12-panel layout?', 'Set 64 × 32 panels, 3 columns, 2 rows and 2 sides? Check chain assignments before applying.', () => {
    [64,32,3,2,2].forEach((n,i) => { field(keys[i]).value=n; }); generate();
  }));
  async function send(action) {
    const buttons = displayForm.querySelectorAll('button'); buttons.forEach(b => { b.disabled=true; });
    const result = document.getElementById('display-result'); result.textContent = action === 'test' ? 'Testing for 15 seconds, then restoring the previous display…' : 'Working…';
    try {
      const body = new URLSearchParams({csrf:displayForm.elements.csrf.value, action, layout:JSON.stringify(layout)});
      const response = await fetch('/display/settings', {method:'POST', body});
      const reply = await response.json();
      result.textContent=reply.message;
      if (!response.ok || !reply.ok) showDialog('Display settings', reply.message);
    } catch (error) {
      result.textContent='The display operation could not be confirmed.';
      showDialog('Connection unavailable', 'Check the controller before trying again.');
    } finally { buttons.forEach(b => { b.disabled=false; }); }
  }
  displayForm.querySelectorAll('[data-display-action]').forEach(button => button.addEventListener('click', () => {
    if (!displayForm.reportValidity()) return;
    const count=layout.columns*layout.rows*layout.sides;
    if (layout.panels.length !== count || new Set(layout.panels.map(p=>p.chain)).size !== count || layout.panels.some(p=>!Number.isInteger(p.chain)||p.chain<1||p.chain>count)) {
      showDialog('Check panel mapping', 'Assign each chain position exactly once.'); return;
    }
    const action=button.dataset.displayAction;
    if (action==='save') send(action);
    else showDialog(action==='test' ? 'Test panel mapping?' : 'Apply display settings?', action==='test' ? 'The controller will restart and show panel numbers with upward arrows for 15 seconds, then restore the previous layout. The current timing session will end.' : 'Apply this layout and restart the display controller? The current timing session will end. Save separately to keep this layout in the editor.', () => send(action));
  }));
  render();
}
