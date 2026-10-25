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
  if (['display-settings', 'clock-time-form', 'clock-lap-form'].includes(form.id)) return;
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

const updateRoot = document.getElementById('software-updates');
if (updateRoot) {
  const element = name => document.getElementById(`update-${name}`);
  const release = element('release');
  const dialog = element('modal');
  let state = null, requested = null, waiting = false, localMessage = null;
  function pill(target, text, tone) {
    const span = document.createElement('span'); span.className = `pill ${tone}`;
    span.textContent = text; target.replaceChildren(span);
  }
  function controls() {
    const option = release.selectedOptions[0];
    element('install').disabled = waiting || !state?.configured || state.busy || !option?.value || option.dataset.installable !== 'yes' || option.value === state.installed;
    element('rollback').disabled = waiting || !state?.configured || state.busy || !state.previous;
    element('check').disabled = waiting || !!state?.busy;
    release.disabled = waiting || !!state?.busy;
    element('notes').textContent = option?.dataset.notes || 'No release notes provided.';
    element('package-message').textContent = option?.value && option.dataset.installable !== 'yes' ? 'An installation package is not available for this release.' : '';
  }
  function render(data, refreshReleases = false) {
    const initial = state === null;
    state = data;
    element('installed').textContent = data.installed;
    element('latest').textContent = data.latest?.version || (data.checked ? 'No releases published' : 'Not checked');
    element('previous').textContent = data.previous || 'None yet';
    element('availability').textContent = data.available ? 'Update available' : data.latest ? 'Up to date' : data.checked ? 'No releases published' : 'Check for releases';
    element('availability').className = `pill ${data.available ? 'info' : 'neutral'}`;
    if (initial || refreshReleases || release.options.length === 1 && data.releases.length) {
      const selected = release.value;
      release.replaceChildren();
      data.releases.forEach(item => {
        const option = document.createElement('option'); option.value = item.version; option.textContent = item.version;
        option.dataset.installable = item.installable ? 'yes' : 'no'; option.dataset.notes = item.notes; release.append(option);
      });
      if (data.releases.some(item => item.version === selected)) release.value = selected;
    }
    pill(element('progress'), localMessage || data.status.message, localMessage ? 'danger' : data.busy ? 'info' : data.status.phase === 'success' ? 'success' : ['failed','error'].includes(data.status.phase) ? 'danger' : 'neutral');
    const body = element('history-body'); body.replaceChildren();
    data.history.forEach(row => {
      const tr = document.createElement('tr');
      const date = new Date(row.date);
      [Number.isNaN(date.getTime()) ? row.date : new Intl.DateTimeFormat(undefined, {dateStyle:'medium',timeStyle:'medium'}).format(date), row.action === 'install' ? 'Install' : 'Rollback', row.previous, row.version].forEach(text => {
        const td = document.createElement('td'); td.textContent = text; tr.append(td);
      });
      const result = document.createElement('td'); pill(result, row.success ? 'Success' : 'Failed', row.success ? 'success' : 'danger');
      const message = document.createElement('p'); message.textContent = row.message; result.append(message); tr.append(result); body.append(tr);
    });
    if (!data.history.length) { const tr=document.createElement('tr'), td=document.createElement('td'); td.colSpan=5; td.textContent='No software changes recorded.'; tr.append(td); body.append(tr); }
    controls();
  }
  async function post(path, fields = {}) {
    const response = await fetch(path, {method:'POST', body:new URLSearchParams({csrf:updateRoot.dataset.csrf, ...fields})});
    if (response.redirected) { location.href = response.url; throw new Error('Please sign in again.'); }
    const reply = await response.json();
    if (!response.ok || !reply.ok) throw new Error(reply.message || 'The operation could not be completed.');
    return reply;
  }
  async function poll() {
    try {
      const response = await fetch('/updates/status');
      if (response.redirected) { location.href=response.url; return; }
      if (!response.ok) throw new Error();
      const data = await response.json();
      if (!waiting) render(data);
    } catch (_) { pill(element('progress'), 'Reconnecting to the dashboard…', 'warning'); }
    setTimeout(poll, 2000);
  }
  element('check').addEventListener('click', async () => {
    waiting=true; localMessage=null; controls(); pill(element('progress'), 'Checking releases…', 'info');
    try { const reply=await post('/updates/check'); render(reply.update,true); }
    catch (error) { localMessage=error.message; pill(element('progress'), error.message, 'danger'); }
    finally { waiting=false; controls(); }
  });
  release.addEventListener('change',controls);
  for (const action of ['install','rollback']) element(action).addEventListener('click', () => {
    requested={action, version:release.value};
    element('modal-title').textContent=action === 'install' ? `Install ${release.value}?` : `Restore ${state.previous}?`;
    element('modal-message').textContent='The display and dashboard will restart. The current timing session will end. Your settings and logos will be kept.';
    dialog.showModal();
  });
  element('cancel').addEventListener('click',()=>dialog.close());
  element('confirm').addEventListener('click',async () => {
    dialog.close(); waiting=true; localMessage=null; controls();
    try { await post('/updates/action',{...requested,confirm:'yes'}); pill(element('progress'),'Software operation started…','info'); }
    catch(error) { localMessage=error.message; pill(element('progress'),error.message,'danger'); }
    finally { waiting=false; controls(); }
  });
  poll();
}

if (document.querySelector('[data-lynx-status]')) {
  const updateLynx = async () => {
    try {
      const response = await fetch('/api/finishlynx');
      if (!response.ok) throw new Error('Status unavailable');
      const state = await response.json();
      const pill = document.querySelector('[data-lynx-status]');
      pill.textContent = state.label;
      pill.className = 'pill ' + state.tone;
      document.querySelector('[data-lynx-running]').textContent = state.running ? 'Running' : 'Stopped';
      document.querySelector('[data-lynx-event]').textContent = state.event || 'Waiting for event';
      document.querySelector('[data-lynx-clock]').textContent = state.clock || (state.event ? '0:00.0' : 'Waiting for time');
    } catch (_) {
      document.querySelector('[data-lynx-status]').textContent = 'Unavailable';
    }
  };
  updateLynx();
  setInterval(updateLynx, 500);
}


function renderClockPreview(next) {
  const image = document.getElementById('clock-preview-image');
  const empty = document.getElementById('clock-preview-empty');
  document.getElementById('clock-current-mode').textContent = next.connected ? next.mode || '—' : '—';
  if (next.connected && next.frame) {
    const source = 'data:image/png;base64,' + next.frame;
    if (image.getAttribute('src') !== source) image.src = source;
    image.hidden = false; empty.hidden = true;
  } else {
    image.hidden = true; image.removeAttribute('src'); empty.hidden = false;
    empty.textContent = next.connected ? 'Waiting for the display…' : 'Clock display unavailable';
  }
}

const clockRoot = document.getElementById('clock-controls');
if (clockRoot) {
  const element = id => document.getElementById(`clock-${id}`);
  const modeButtons = [...clockRoot.querySelectorAll('[data-clock-mode]')];
  let state = null, waiting = false;
  function controls() {
    const connected = !!state?.connected;
    const timed = ['Count Up', 'Count Down', 'Round Counter'].includes(state?.mode);
    element('time-form').hidden = !timed;
    element('lap-controls').hidden = state?.mode !== 'Lap Counter';
    element('finishlynx-link').hidden = state?.mode !== 'FinishLynx';
    clockRoot.querySelectorAll('button').forEach(button => { button.disabled = waiting || !connected; });
    element('start').disabled = waiting || !connected || !timed || !['ready','paused'].includes(state?.phase) || (state?.mode === 'Count Down' && state.value === 0);
    element('pause').disabled = waiting || !connected || !timed || state?.phase !== 'running';
    modeButtons.forEach(button => { button.setAttribute('aria-pressed', String(button.dataset.clockMode === state?.mode)); });
  }
  function render(next) {
    state = next;
    const labels = {menu:'Select a mode',entry:'Set time',ready:'Ready',running:'Running',paused:'Paused',unavailable:'Disconnected'};
    const tone = !next.connected ? 'warning' : next.phase === 'running' ? 'success' : 'info';
    element('state').textContent = next.connected ? (labels[next.phase] || 'Connected') : 'Disconnected';
    element('state').className = `pill ${tone}`;
    renderClockPreview(next);
    if (next.mode === 'Lap Counter' && next.value !== null) element('lap-number').textContent = next.value;
    controls();
  }
  async function refresh() {
    const response = await fetch('/api/controller/status');
    if (response.redirected) { location.href = response.url; return; }
    if (!response.ok) throw new Error();
    const next = await response.json();
    if (!waiting) render(next);
  }
  async function send(action, mode = state?.mode, fields = {}) {
    if (waiting) return;
    waiting = true; controls(); element('result').textContent = 'Working…'; element('result').className = '';
    try {
      const response = await fetch('/api/controller/mode', {method:'POST', body:new URLSearchParams({csrf:clockRoot.dataset.csrf, action, mode, ...fields})});
      if (response.redirected) { location.href = response.url; return; }
      const reply = await response.json();
      element('result').textContent = reply.message;
      element('result').className = `pill ${response.ok && reply.ok ? 'success' : 'danger'}`;
    } catch (_) {
      element('result').textContent = 'Change could not be confirmed. Check the clock before trying again.';
      element('result').className = 'pill warning';
    } finally {
      waiting = false;
      try { await refresh(); } catch (_) { render({connected:false}); }
      controls();
    }
  }
  modeButtons.forEach(button => button.addEventListener('click', () => send('select', button.dataset.clockMode)));
  element('time-form').addEventListener('submit', event => { event.preventDefault(); if (event.target.reportValidity()) send('set_time', state.mode, {time:element('time').value}); });
  element('start').addEventListener('click', () => send('start'));
  element('pause').addEventListener('click', () => send('pause'));
  clockRoot.querySelectorAll('[data-clock-action]').forEach(button => button.addEventListener('click', () => send(button.dataset.clockAction)));
  element('lap-form').addEventListener('submit', event => { event.preventDefault(); if (event.target.reportValidity()) send('lap_set', 'Lap Counter', {number:element('lap-input').value}); });
  async function poll() {
    try { await refresh(); } catch (_) { if (!waiting) render({connected:false}); }
    setTimeout(poll, 350);
  }
  controls(); poll();
}


const finishLynxButton = document.getElementById('activate-finishlynx');
if (finishLynxButton) {
  let working = false;
  const result = document.getElementById('finishlynx-mode-result');
  async function updateMode() {
    try {
      const response = await fetch('/api/controller/status');
      if (response.redirected) { location.href = response.url; return; }
      if (!response.ok) throw new Error();
      const state = await response.json();
      if (!working) {
        const active = state.connected && state.mode === 'FinishLynx' && state.phase === 'running';
        finishLynxButton.disabled = active;
        finishLynxButton.textContent = active ? 'FinishLynx mode active' : 'Use FinishLynx mode';
      }
    } catch (_) {
      if (!working) { finishLynxButton.disabled = false; finishLynxButton.textContent = 'Use FinishLynx mode'; }
    }
  }
  finishLynxButton.addEventListener('click', async () => {
    if (working) return;
    working = true; finishLynxButton.disabled = true; finishLynxButton.textContent = 'Switching…';
    result.textContent = ''; result.className = '';
    try {
      const response = await fetch('/api/controller/mode', {method:'POST', body:new URLSearchParams({csrf:finishLynxButton.dataset.csrf, action:'select', mode:'FinishLynx'})});
      if (response.redirected) { location.href = response.url; return; }
      const reply = await response.json();
      result.textContent = response.ok && reply.ok ? 'Clock set to FinishLynx.' : reply.message;
      result.className = `pill ${response.ok && reply.ok ? 'success' : 'danger'}`;
    } catch (_) {
      result.textContent = 'Mode could not be confirmed. Check the clock and try again.';
      result.className = 'pill warning';
    } finally {
      working = false; finishLynxButton.disabled = false; finishLynxButton.textContent = 'Use FinishLynx mode';
      await updateMode();
    }
  });
  const pollMode = async () => { await updateMode(); setTimeout(pollMode, 1500); };
  pollMode();
}
