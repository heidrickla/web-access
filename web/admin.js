// The management plane. Served as a file: the CSP allows `script-src 'self'` only.

const $ = id => document.getElementById(id);
const say = (text, bad = false) => {
  $('status').textContent = text;
  $('status').classList.toggle('bad', bad);
};

/* ---- helpers ------------------------------------------------------------------------------ */

async function api(method, path, body, raw) {
  const init = { method, cache: 'no-store', headers: {} };
  if (raw !== undefined) {
    init.body = raw;
    init.headers['Content-Type'] = 'application/zip';
  } else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, init);
  if (res.status === 401) {
    location.href = './';
    throw new Error('signed out');
  }
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || ('HTTP ' + res.status));
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

/// Build an element. Text always goes in as textContent: names come from administrators and users.
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) e.append(c);
  return e;
}

const when = unix => (unix ? new Date(unix * 1000).toLocaleString() : 'never');

function fail(err) {
  say(err.message, true);
}

/* ---- tabs --------------------------------------------------------------------------------- */

const loaders = {};
let current = 'users';

function showTab(name) {
  current = name;
  for (const b of $('tabs').querySelectorAll('button')) b.classList.toggle('active', b.dataset.tab === name);
  for (const s of document.querySelectorAll('main > section')) s.hidden = s.id !== 'tab-' + name;
  history.replaceState(null, '', '#' + name);
  loaders[name]().catch(fail);
}

$('tabs').addEventListener('click', ev => {
  const b = ev.target.closest('button[data-tab]');
  if (b) showTab(b.dataset.tab);
});

async function refreshBanner() {
  const m = await api('GET', '/api/admin/migration');
  const notes = [];
  if (m.frozen) notes.push('This proxy is frozen for migration: saved credentials and admin changes are refused until it is unfrozen on the Migration tab.');
  if (!m.unlocked) notes.push('The credential store is locked on this host. Unlock it on the Migration tab with the recovery passphrase.');
  else if (!m.recovery_set) notes.push('Users cannot save credentials until a recovery passphrase is set on the Migration tab.');
  $('banner').hidden = notes.length === 0;
  $('banner').textContent = notes.join(' ');
  return m;
}

/* ---- shared data -------------------------------------------------------------------------- */

let users = [];
let serverList = [];
let groupList = [];

async function loadCatalogue() {
  const [s, g] = await Promise.all([api('GET', '/api/admin/servers'), api('GET', '/api/admin/groups')]);
  serverList = s.servers;
  groupList = g.groups;
}

/// Servers grouped in the order users see them: groups by their order, then ungrouped.
function serversByGroup() {
  const out = groupList.map(g => ({ id: g.id, name: g.name, servers: [] }));
  const byId = new Map(out.map(g => [g.id, g]));
  const ungrouped = { id: null, name: 'Ungrouped', servers: [] };
  for (const s of serverList) (byId.get(s.group_id) || ungrouped).servers.push(s);
  for (const g of out) g.servers.sort((a, b) => a.name.localeCompare(b.name));
  ungrouped.servers.sort((a, b) => a.name.localeCompare(b.name));
  return [...out, ungrouped].filter(g => g.servers.length);
}

/* ---- users -------------------------------------------------------------------------------- */

let selected = null;          // user id
let assigned = new Set();     // working copy for the selected user
let savedAssigned = new Set();

loaders.users = async () => {
  const [u] = await Promise.all([api('GET', '/api/admin/users'), loadCatalogue()]);
  users = u.users;
  renderUsers();
  if (selected && users.some(x => x.id === selected)) await selectUser(selected);
  else $('user-detail').hidden = true;
  say(users.length + ' users');
};

function renderUsers() {
  const q = $('user-filter').value.trim().toLowerCase();
  const body = $('user-table').tBodies[0];
  body.innerHTML = '';
  for (const u of users) {
    if (q && !(u.username + ' ' + (u.display_name || '')).toLowerCase().includes(q)) continue;
    const name = el('td', {}, u.username);
    if (u.is_admin || u.bootstrap_admin) name.append(el('span', { class: 'tag good', text: 'admin' }));
    if (u.sid_mismatch) name.append(el('span', { class: 'tag warn', text: 'check account' }));
    const tr = el('tr', { class: 'pick' + (u.id === selected ? ' selected' : ''), onclick: () => selectUser(u.id).catch(fail) },
      name,
      el('td', { text: u.display_name || '' }),
      el('td', { class: 'num', text: String(u.servers) }),
      el('td', { text: when(u.last_login) }));
    body.append(tr);
  }
}

$('user-filter').addEventListener('input', renderUsers);

$('add-user').addEventListener('submit', async ev => {
  ev.preventDefault();
  try {
    const r = await api('POST', '/api/admin/users', { username: $('new-username').value });
    $('new-username').value = '';
    selected = r.id;
    say(r.verified ? 'user added; found in the directory' : 'user added');
    await loaders.users();
  } catch (err) { fail(err); }
});

async function selectUser(id) {
  selected = id;
  const u = users.find(x => x.id === id);
  if (!u) return;
  const r = await api('GET', `/api/admin/users/${id}/servers`);
  assigned = new Set(r.assigned);
  savedAssigned = new Set(r.assigned);
  renderUsers();

  $('user-detail').hidden = false;
  $('ud-title').textContent = u.display_name ? `${u.display_name} (${u.username})` : u.username;
  const facts = $('ud-facts');
  facts.innerHTML = '';
  const binding = u.sid_mismatch
    ? 'a different account with this username tried to sign in; reset the binding only if the account was legitimately recreated'
    : (u.sid_bound ? 'bound at first sign-in' : 'binds at first sign-in');
  for (const [k, v] of [
    ['Added', when(u.created)],
    ['Last sign-in', when(u.last_login)],
    ['Saved credentials', String(u.saved)],
    ['Account binding', binding],
  ]) facts.append(el('dt', { text: k }), el('dd', { text: v }));

  $('ud-admin').checked = u.is_admin || u.bootstrap_admin;
  $('ud-admin').disabled = u.bootstrap_admin;
  $('ud-admin').title = u.bootstrap_admin ? 'An administrator by config.toml' : '';
  $('ud-reset').hidden = !u.sid_bound && !u.sid_mismatch;

  const from = $('ud-copy-from');
  from.innerHTML = '';
  for (const o of users) if (o.id !== id) from.append(el('option', { value: String(o.id), text: `${o.username} (${o.servers})` }));
  $('ud-copy').disabled = from.options.length === 0;

  renderChecklist();
}

function renderChecklist() {
  const q = $('ud-filter').value.trim().toLowerCase();
  const root = $('ud-checklist');
  root.innerHTML = '';
  for (const g of serversByGroup()) {
    const visible = g.servers.filter(s => !q || (s.name + ' ' + s.host).toLowerCase().includes(q));
    if (!visible.length) continue;
    const count = el('span', { class: 'gcount' });
    const all = el('input', { type: 'checkbox', title: 'Select all in ' + g.name });
    const sync = () => {
      const n = g.servers.filter(s => assigned.has(s.id)).length;
      count.textContent = `${n} / ${g.servers.length}`;
      all.checked = n === g.servers.length;
      all.indeterminate = n > 0 && n < g.servers.length;
    };
    all.addEventListener('click', ev => ev.stopPropagation());
    all.addEventListener('change', () => {
      for (const s of visible) all.checked ? assigned.add(s.id) : assigned.delete(s.id);
      renderChecklist();
    });
    const summary = el('summary', {}, all, el('span', { class: 'gname', text: g.name }), count);
    const ul = el('ul', { class: 'rows' });
    for (const s of visible) {
      const box = el('input', { type: 'checkbox' });
      box.checked = assigned.has(s.id);
      box.addEventListener('change', () => {
        box.checked ? assigned.add(s.id) : assigned.delete(s.id);
        sync();
        showChanges();
      });
      ul.append(el('li', { class: 'row' }, el('label', {}, box, el('span', { text: s.name })), el('span', { class: 'host', text: s.host })));
    }
    const details = el('details', { class: 'group' }, summary, ul);
    details.open = !!q || g.servers.some(s => assigned.has(s.id)) || serversByGroup().length <= 3;
    root.append(details);
    sync();
  }
  if (!root.children.length) root.append(el('p', { class: 'empty', text: serverList.length ? 'No servers match.' : 'No servers yet. Add them on the Servers tab.' }));
  showChanges();
}

function showChanges() {
  const added = [...assigned].filter(x => !savedAssigned.has(x)).length;
  const removed = [...savedAssigned].filter(x => !assigned.has(x)).length;
  $('ud-changes').textContent = added || removed
    ? `Unsaved: ${added} to add, ${removed} to remove. ${assigned.size} assigned in total.`
    : `${assigned.size} assigned.`;
  $('ud-save').disabled = !(added || removed);
}

$('ud-filter').addEventListener('input', renderChecklist);

$('ud-save').addEventListener('click', async () => {
  try {
    const r = await api('PUT', `/api/admin/users/${selected}/servers`, { server_ids: [...assigned] });
    say(`saved: ${r.added} added, ${r.removed} removed`);
    await loaders.users();
  } catch (err) { fail(err); }
});

$('ud-admin').addEventListener('change', async () => {
  try {
    await api('PATCH', `/api/admin/users/${selected}`, { is_admin: $('ud-admin').checked });
    say('saved');
    await loaders.users();
  } catch (err) { fail(err); }
});

$('ud-reset').addEventListener('click', async () => {
  const u = users.find(x => x.id === selected);
  if (!confirm(`Reset the account binding for ${u.username}? Their saved credentials are removed and the next sign-in binds the account again.`)) return;
  try {
    await api('POST', `/api/admin/users/${selected}/clear-sid`);
    say('binding reset');
    await loaders.users();
  } catch (err) { fail(err); }
});

$('ud-remove').addEventListener('click', async () => {
  const u = users.find(x => x.id === selected);
  if (!confirm(`Remove ${u.username}? Their server list and saved credentials are removed, and any open session is ended.`)) return;
  try {
    await api('DELETE', `/api/admin/users/${selected}`);
    selected = null;
    say('user removed');
    await loaders.users();
  } catch (err) { fail(err); }
});

$('ud-copy').addEventListener('click', async () => {
  const from = Number($('ud-copy-from').value);
  try {
    const r = await api('POST', `/api/admin/users/${selected}/copy-from/${from}`);
    say(`${r.added} server(s) added`);
    await loaders.users();
  } catch (err) { fail(err); }
});

/* ---- servers ------------------------------------------------------------------------------ */

let editing = null;

loaders.servers = async () => {
  await loadCatalogue();
  const sel = $('sf-group');
  const keep = sel.value;
  sel.innerHTML = '';
  sel.append(el('option', { value: '', text: '(no group)' }));
  for (const g of groupList) sel.append(el('option', { value: String(g.id), text: g.name }));
  sel.value = keep;
  renderServers();
  say(serverList.length + ' servers');
};

function groupName(id) {
  const g = groupList.find(x => x.id === id);
  return g ? g.name : '';
}

function renderServers() {
  const q = $('server-filter').value.trim().toLowerCase();
  const body = $('server-table').tBodies[0];
  body.innerHTML = '';
  for (const s of [...serverList].sort((a, b) => a.name.localeCompare(b.name))) {
    if (q && !(s.name + ' ' + s.host + ' ' + groupName(s.group_id)).toLowerCase().includes(q)) continue;
    body.append(el('tr', {},
      el('td', { text: s.name }),
      el('td', { text: s.host }),
      el('td', { class: 'num', text: String(s.port) }),
      el('td', { text: groupName(s.group_id) }),
      el('td', { class: 'num', text: String(s.assigned) }),
      el('td', { class: 'actions' },
        el('button', { class: 'ghost', text: 'Edit', onclick: () => editServer(s) }),
        el('button', { class: 'danger', text: 'Delete', onclick: () => deleteServer(s) }))));
  }
}

$('server-filter').addEventListener('input', renderServers);

function editServer(s) {
  editing = s.id;
  $('server-form-title').textContent = 'Edit ' + s.name;
  $('sf-name').value = s.name;
  $('sf-host').value = s.host;
  $('sf-port').value = s.port;
  $('sf-group').value = s.group_id === null ? '' : String(s.group_id);
  $('sf-go').textContent = 'Save changes';
  $('sf-cancel').hidden = false;
  $('sf-name').focus();
}

function resetServerForm() {
  editing = null;
  $('server-form').reset();
  $('sf-port').value = 3389;
  $('server-form-title').textContent = 'Add a server';
  $('sf-go').textContent = 'Add server';
  $('sf-cancel').hidden = true;
}

$('sf-cancel').addEventListener('click', resetServerForm);

$('server-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const body = {
    name: $('sf-name').value,
    host: $('sf-host').value,
    port: Number($('sf-port').value) || 3389,
    group_id: $('sf-group').value ? Number($('sf-group').value) : null,
  };
  try {
    if (editing) await api('PATCH', `/api/admin/servers/${editing}`, body);
    else await api('POST', '/api/admin/servers', body);
    say(editing ? 'server saved' : 'server added');
    resetServerForm();
    await loaders.servers();
  } catch (err) { fail(err); }
});

async function deleteServer(s) {
  if (!confirm(`Delete ${s.name}? It is removed from ${s.assigned} user(s), with their saved credentials for it, and any open session to it is ended.`)) return;
  try {
    await api('DELETE', `/api/admin/servers/${s.id}`);
    say('server deleted');
    await loaders.servers();
  } catch (err) { fail(err); }
}

$('csv-file').addEventListener('change', async ev => {
  const f = ev.target.files[0];
  if (f) $('csv-text').value = await f.text();
});

$('csv-go').addEventListener('click', async () => {
  const list = $('csv-errors');
  list.hidden = true;
  list.innerHTML = '';
  try {
    const r = await api('POST', '/api/admin/servers/import', { csv: $('csv-text').value });
    say(`imported: ${r.created} created, ${r.updated} updated`);
    $('csv-text').value = '';
    $('csv-file').value = '';
    await loaders.servers();
  } catch (err) {
    fail(err);
    if (err.data && err.data.lines) {
      for (const line of err.data.lines) list.append(el('li', { text: line }));
      list.hidden = false;
    }
  }
});

/* ---- groups ------------------------------------------------------------------------------- */

loaders.groups = async () => {
  await loadCatalogue();
  renderGroups();
  say(groupList.length + ' groups');
};

function renderGroups() {
  const body = $('group-table').tBodies[0];
  body.innerHTML = '';
  groupList.forEach((g, i) => {
    const up = el('button', { class: 'ghost', text: 'Up', onclick: () => moveGroup(i, -1) });
    const down = el('button', { class: 'ghost', text: 'Down', onclick: () => moveGroup(i, 1) });
    up.disabled = i === 0;
    down.disabled = i === groupList.length - 1;
    const del = el('button', { class: 'danger', text: 'Delete', onclick: () => deleteGroup(g) });
    del.disabled = g.servers > 0;
    del.title = g.servers > 0 ? 'Move or delete its servers first' : '';
    body.append(el('tr', {},
      el('td', { text: g.name }),
      el('td', { class: 'num', text: String(g.servers) }),
      el('td', { class: 'actions' }, up, down,
        el('button', { class: 'ghost', text: 'Rename', onclick: () => renameGroup(g) }), del)));
  });
}

async function moveGroup(i, by) {
  const ids = groupList.map(g => g.id);
  const [id] = ids.splice(i, 1);
  ids.splice(i + by, 0, id);
  try {
    await api('POST', '/api/admin/groups/order', { ids });
    await loaders.groups();
  } catch (err) { fail(err); }
}

async function renameGroup(g) {
  const name = prompt('New name for ' + g.name, g.name);
  if (!name || name === g.name) return;
  try {
    await api('PATCH', `/api/admin/groups/${g.id}`, { name });
    say('group renamed');
    await loaders.groups();
  } catch (err) { fail(err); }
}

async function deleteGroup(g) {
  if (!confirm(`Delete the group ${g.name}?`)) return;
  try {
    await api('DELETE', `/api/admin/groups/${g.id}`);
    say('group deleted');
    await loaders.groups();
  } catch (err) { fail(err); }
}

$('add-group').addEventListener('submit', async ev => {
  ev.preventDefault();
  try {
    await api('POST', '/api/admin/groups', { name: $('new-group').value });
    $('new-group').value = '';
    say('group added');
    await loaders.groups();
  } catch (err) { fail(err); }
});

/* ---- activity ----------------------------------------------------------------------------- */

let oldest = null;

loaders.activity = async () => {
  oldest = null;
  $('audit-table').tBodies[0].innerHTML = '';
  await loadAudit();
};

async function loadAudit() {
  const r = await api('GET', '/api/admin/audit?limit=100' + (oldest ? '&before=' + oldest : ''));
  const body = $('audit-table').tBodies[0];
  for (const e of r.entries) {
    body.append(el('tr', {},
      el('td', { text: when(e.at) }),
      el('td', { text: e.actor }),
      el('td', { text: e.action }),
      el('td', { text: e.detail })));
    oldest = e.id;
  }
  $('audit-more').disabled = r.entries.length < 100;
  say(body.rows.length + ' entries');
}

$('audit-more').addEventListener('click', () => loadAudit().catch(fail));

/* ---- migration ---------------------------------------------------------------------------- */

let migration = null;
let upload = null;

loaders.migration = async () => {
  migration = await refreshBanner();
  const m = migration;
  const facts = $('mig-facts');
  facts.innerHTML = '';
  for (const [k, v] of [
    ['Host name', m.host],
    ['Users', String(m.counts.users)],
    ['Servers', String(m.counts.servers)],
    ['Assignments', String(m.counts.assignments)],
    ['Saved credentials', String(m.counts.credentials)],
    ['Open RDP sessions', String(m.live_sessions)],
    ['Recovery passphrase', m.recovery_set ? 'set' : 'not set'],
    ['Credential store', m.unlocked ? 'unlocked' : 'locked'],
    ['Frozen for migration', m.frozen ? 'yes' : 'no'],
  ]) facts.append(el('dt', { text: k }), el('dd', { text: v }));

  $('unlock-card').hidden = m.unlocked;
  $('rec-current-label').hidden = !m.recovery_set;
  $('recovery-title').textContent = m.recovery_set ? 'Change the recovery passphrase' : 'Set a recovery passphrase';
  $('rec-go').textContent = m.recovery_set ? 'Change passphrase' : 'Set passphrase';
  $('unfreeze').hidden = !m.frozen;

  const dir = m.directory;
  $('directory-card').hidden = !dir.service_account;
  $('directory-note').textContent = dir.service_account
    ? `Account ${dir.service_account}. Password ${dir.password_set ? 'is set' : 'is not set'}. It lets the proxy check accounts when they are added, and end the sessions of accounts disabled in the directory.`
    : '';
  say('migration');
};

$('recovery-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  if ($('rec-new').value !== $('rec-repeat').value) return say('the two entries differ', true);
  try {
    await api('POST', '/api/admin/migration/recovery', {
      current: migration.recovery_set ? $('rec-current').value : null,
      new: $('rec-new').value,
    });
    $('recovery-form').reset();
    say('recovery passphrase saved');
    await loaders.migration();
  } catch (err) { fail(err); }
});

$('unlock-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  try {
    await api('POST', '/api/admin/migration/unlock', { passphrase: $('unlock-pass').value });
    $('unlock-pass').value = '';
    say('credential store unlocked');
    await loaders.migration();
  } catch (err) { fail(err); }
});

$('directory-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  try {
    const r = await api('POST', '/api/admin/settings/directory-password', { password: $('dir-pass').value });
    $('dir-pass').value = '';
    say(r.verified ? 'password verified and saved' : 'saved; the directory could not be reached to verify it', !r.verified);
    await loaders.migration();
  } catch (err) { fail(err); }
});

$('export-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const go = $('exp-go');
  go.disabled = true;
  say('exporting');
  try {
    const res = await fetch('/api/admin/migration/export', {
      method: 'POST',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: $('exp-pass').value, freeze: $('exp-freeze').checked }),
    });
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { msg = (await res.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    const disposition = res.headers.get('Content-Disposition') || '';
    const name = (/filename="([^"]+)"/.exec(disposition) || [])[1] || 'web-access-export.zip';
    const url = URL.createObjectURL(await res.blob());
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    $('exp-pass').value = '';
    say('exported ' + name);
    await loaders.migration();
  } catch (err) {
    fail(err);
  } finally {
    go.disabled = false;
  }
});

$('unfreeze').addEventListener('click', async () => {
  try {
    await api('POST', '/api/admin/migration/unfreeze');
    say('unfrozen');
    await loaders.migration();
  } catch (err) { fail(err); }
});

$('import-upload').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = $('imp-file').files[0];
  if (!f) return;
  const go = $('imp-upload-go');
  go.disabled = true;
  say('uploading');
  try {
    upload = await api('POST', '/api/admin/migration/import', undefined, f);
    const m = upload.manifest;
    const facts = $('imp-facts');
    facts.innerHTML = '';
    for (const [k, v] of [
      ['Exported from', m.source_host],
      ['Exported at', when(m.exported_at)],
      ['Users', String(m.counts.users)],
      ['Servers', String(m.counts.servers)],
      ['Assignments', String(m.counts.assignments)],
      ['Saved credentials', String(m.counts.credentials)],
    ]) facts.append(el('dt', { text: k }), el('dd', { text: v }));
    $('imp-host-label').hidden = !upload.holds_data;
    $('imp-host-hint').textContent = `This proxy holds ${upload.current.users} user(s) and ${upload.current.servers} server(s). Type its name, ${upload.this_host}, to replace them`;
    $('import-upload').hidden = true;
    $('import-confirm').hidden = false;
    say('check the export, then import');
  } catch (err) {
    fail(err);
  } finally {
    go.disabled = false;
  }
});

$('imp-cancel').addEventListener('click', () => {
  upload = null;
  $('import-confirm').reset();
  $('import-confirm').hidden = true;
  $('import-upload').hidden = false;
  $('import-upload').reset();
});

$('import-confirm').addEventListener('submit', async ev => {
  ev.preventDefault();
  const go = $('imp-go');
  go.disabled = true;
  say('importing');
  try {
    const r = await api('POST', `/api/admin/migration/import/${upload.upload_id}`, {
      passphrase: $('imp-pass').value,
      confirm_host: $('imp-host').value || null,
    });
    const c = r.counts;
    $('imp-cancel').click();
    say(`imported ${c.users} users, ${c.servers} servers, ${c.credentials} saved credentials`);
    // The imported sign-in sessions replace this host's, so this page may need a fresh sign-in.
    await loaders.migration();
  } catch (err) {
    fail(err);
  } finally {
    go.disabled = false;
  }
});

/* ---- start -------------------------------------------------------------------------------- */

(async () => {
  let me;
  try {
    me = await api('GET', '/api/me');
  } catch {
    return;
  }
  $('who').textContent = me.display_name || me.username;
  if (!me.is_admin) {
    $('denied').hidden = false;
    say('administrators only', true);
    return;
  }
  $('tabs').hidden = false;
  try { await refreshBanner(); } catch (err) { fail(err); }
  const first = location.hash.slice(1);
  showTab(loaders[first] ? first : 'users');
})();
