// Served as a file, not inlined: the proxy's Content-Security-Policy allows `script-src 'self'`.

import init, { setup, SessionBuilder, DesktopSize, DeviceEvent, InputTransaction, ClipboardData, Extension }
  from './ironrdp_web.js';

const $ = id => document.getElementById(id);
const canvas = $('screen');
const say = (text, bad = false) => {
  $('status').textContent = text;
  $('status').classList.toggle('bad', bad);
};

// Same origin as the page, so there is nothing to configure and no way to point the client elsewhere.
const proxyAddress = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';

let session = null;
let servers = new Map();   // id -> server, from the last list load

// The RDP client loads in the background while the user signs in and picks a server.
const clientReady = (async () => {
  await init();
  setup('info');
})();
clientReady.catch(err => say('the RDP client failed to load: ' + describe(err), true));

/* ---- API ---------------------------------------------------------------------------------- */

class SignedOut extends Error {}

// The database the ids on this page came from. Every request carries it; the proxy refuses a change
// from a page loaded before an import, and a page that sees another one reloads.
let dataInstance = null;

async function api(method, path, body) {
  const headers = body === undefined ? {} : { 'Content-Type': 'application/json' };
  if (dataInstance) headers['X-Data-Instance'] = dataInstance;
  const res = await fetch(path, {
    method,
    cache: 'no-store',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const instance = res.headers.get('X-Data-Instance');
  if (instance && dataInstance && instance !== dataInstance) {
    location.reload();
    throw new Error("this proxy's data was replaced; reloading");
  }
  if (instance) dataInstance = instance;
  if (res.status === 401 && path !== '/api/login') throw new SignedOut();
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
  return data;
}

/* ---- views -------------------------------------------------------------------------------- */

function show(view) {
  $('login').hidden = view !== 'login';
  $('list').hidden = view !== 'list';
  const signedIn = view === 'list';
  $('signout').hidden = !signedIn;
  if (!signedIn) {
    $('admin-link').hidden = true;
    $('who').textContent = '';
  }
}

function showLogin(message) {
  show('login');
  say('sign in');
  const err = $('login-error');
  err.hidden = !message;
  err.textContent = message || '';
  $('lp').value = '';
  ($('lu').value ? $('lp') : $('lu')).focus();
}

async function showList() {
  let me;
  try {
    me = await api('GET', '/api/me');
  } catch (err) {
    if (err instanceof SignedOut) return showLogin();
    return say('could not reach the proxy: ' + describe(err), true);
  }
  $('who').textContent = me.display_name || me.username;
  $('admin-link').hidden = !me.is_admin;
  show('list');
  await loadServers();
}

$('login-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const go = $('login-go');
  go.disabled = true;
  $('login-error').hidden = true;
  say('signing in');
  try {
    await api('POST', '/api/login', { username: $('lu').value, password: $('lp').value });
    $('lp').value = '';
    await showList();
  } catch (err) {
    showLogin(err.message);
  } finally {
    go.disabled = false;
  }
});

$('signout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch { /* signed out either way */ }
  showLogin();
});

/* ---- the server list ---------------------------------------------------------------------- */

// Which groups are collapsed, remembered per browser. Storage can be unavailable; the list works
// the same without it.
const COLLAPSED_KEY = 'wa:collapsed';
function loadCollapsed() {
  try { return new Set(JSON.parse(localStorage.getItem(COLLAPSED_KEY) || '[]')); } catch { return new Set(); }
}
function saveCollapsed(set) {
  try { localStorage.setItem(COLLAPSED_KEY, JSON.stringify([...set])); } catch { /* not persisted */ }
}
let collapsed = loadCollapsed();

const SAVED_ICON = 'M7 14a5 5 0 1 1 4.9-6h9.1v3h-2v3h-3v-3h-4.1A5 5 0 0 1 7 14zm0-3a2 2 0 1 0 0-4 2 2 0 0 0 0 4z';

function icon(path, title) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '14');
  svg.setAttribute('height', '14');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('d', path);
  p.setAttribute('fill', 'currentColor');
  svg.append(p);
  const span = document.createElement('span');
  span.className = 'mark saved';
  span.title = title;
  span.append(svg);
  return span;
}

async function loadServers() {
  let data;
  try {
    data = await api('GET', '/api/me/servers');
  } catch (err) {
    if (err instanceof SignedOut) return showLogin();
    return say('could not load your servers: ' + describe(err), true);
  }
  renderServers(data.groups || []);
}

function renderServers(groups) {
  const root = $('groups');
  root.innerHTML = '';
  servers = new Map();
  let total = 0;
  for (const g of groups) {
    const key = g.name || '';
    const details = document.createElement('details');
    details.className = 'group';
    details.dataset.key = key;
    details.open = !collapsed.has(key);

    const summary = document.createElement('summary');
    // Recorded on the click itself, not on `toggle`: that event is queued, fires for programmatic
    // changes too, and can be lost to a navigation that follows the click.
    summary.addEventListener('click', () => {
      if ($('filter').value) return;   // filtering opens groups; that is not the user's choice
      if (details.open) collapsed.add(key); else collapsed.delete(key);   // state before the toggle
      saveCollapsed(collapsed);
    });
    const name = document.createElement('span');
    name.className = 'gname';
    name.textContent = g.name || 'Ungrouped';
    const count = document.createElement('span');
    count.className = 'gcount';
    count.textContent = g.servers.length;
    summary.append(name, count);

    const ul = document.createElement('ul');
    ul.className = 'rows';
    for (const s of g.servers) {
      servers.set(s.id, s);
      total++;
      const li = document.createElement('li');
      li.className = 'row';
      li.dataset.search = (s.name + ' ' + s.host).toLowerCase();

      const open = document.createElement('button');
      open.className = 'srv';
      open.textContent = s.name;   // textContent, never innerHTML: names come from administrators
      open.addEventListener('click', () => openServer(s.id));

      const host = document.createElement('span');
      host.className = 'host';
      host.textContent = s.host;

      const marks = document.createElement('span');
      marks.className = 'marks';
      if (s.connected) {
        const m = document.createElement('span');
        m.className = 'mark live';
        m.textContent = 'Connected';
        marks.append(m);
      } else if (s.reconnect) {
        const m = document.createElement('span');
        m.className = 'mark reconnect';
        m.textContent = 'Reconnect';
        m.title = 'Your desktop on this server is still running';
        marks.append(m);
      }
      if (s.saved) marks.append(icon(SAVED_ICON, 'Credentials saved'));

      li.append(open, host, marks);
      if (s.saved) {
        const forget = document.createElement('button');
        forget.className = 'forget ghost';
        forget.textContent = 'Forget';
        forget.title = 'Forget the saved credentials for ' + s.name;
        forget.addEventListener('click', () => forgetCredential(s.id));
        li.append(forget);
      }
      ul.append(li);
    }
    details.append(summary, ul);
    root.append(details);
  }
  $('empty').hidden = total > 0;
  $('list').querySelector('.toolbar').hidden = total === 0;
  applyFilter();
  say(total === 1 ? '1 server' : total + ' servers');
}

function applyFilter() {
  const q = $('filter').value.trim().toLowerCase();
  for (const details of $('groups').querySelectorAll('details.group')) {
    let visible = 0;
    for (const li of details.querySelectorAll('li.row')) {
      const hit = !q || li.dataset.search.includes(q);
      li.hidden = !hit;
      if (hit) visible++;
    }
    details.hidden = visible === 0;
    // A filter opens every group holding a match; clearing it restores the user's own choice.
    details.open = q ? visible > 0 : !collapsed.has(details.dataset.key);
  }
}

$('filter').addEventListener('input', applyFilter);
$('expand-all').addEventListener('click', () => {
  collapsed.clear();
  saveCollapsed(collapsed);
  applyFilter();
});
$('collapse-all').addEventListener('click', () => {
  collapsed = new Set([...$('groups').querySelectorAll('details.group')].map(d => d.dataset.key));
  saveCollapsed(collapsed);
  applyFilter();
});

async function forgetCredential(id) {
  const s = servers.get(id);
  try {
    await api('DELETE', '/api/credentials/' + id);
    say('forgot the saved credentials for ' + (s ? s.name : 'that server'));
  } catch (err) {
    if (err instanceof SignedOut) return showLogin();
    say('could not forget them: ' + err.message, true);
  }
  loadServers();
}

// IronError exposes backtrace(), kind() and rdcleanpathDetails() as METHODS. Reading `err.backtrace`
// without calling it is truthy, so stringifying it printed the function's source instead of the
// failure.
function describe(err) {
  if (!err) return 'unknown error';
  const parts = [];
  for (const name of ['kind', 'backtrace']) {
    if (typeof err[name] === 'function') {
      try {
        const value = err[name]();
        if (value !== undefined && value !== null && String(value) !== '') parts.push(String(value));
      } catch { /* an accessor that throws must not replace the error with its own */ }
    }
  }
  if (typeof err.rdcleanpathDetails === 'function') {
    try {
      const d = err.rdcleanpathDetails();
      if (d) parts.push('rdcleanpath: ' + JSON.stringify(d, Object.keys(d)));
    } catch { /* optional detail */ }
  }
  if (!parts.length && err.message) return err.message;
  return parts.length ? parts.join(' — ') : String(err);
}

/* ---- input -------------------------------------------------------------------------------- */

const send = event => {
  if (!session) return;
  const tx = new InputTransaction();
  tx.addEvent(event);
  session.applyInputs(tx);
};

// Printable keys go through unicode; the rest need scancodes. Anything outside both is dropped
// rather than guessed at.
const SCANCODE = {
  Escape:0x01, Backspace:0x0E, Tab:0x0F, Enter:0x1C, ControlLeft:0x1D, ShiftLeft:0x2A,
  ShiftRight:0x36, AltLeft:0x38, Space:0x39, CapsLock:0x3A, F1:0x3B, F2:0x3C, F3:0x3D, F4:0x3E,
  F5:0x3F, F6:0x40, F7:0x41, F8:0x42, F9:0x43, F10:0x44, F11:0x57, F12:0x58,
  Home:0xE047, ArrowUp:0xE048, PageUp:0xE049, ArrowLeft:0xE04B, ArrowRight:0xE04D,
  End:0xE04F, ArrowDown:0xE050, PageDown:0xE051, Insert:0xE052, Delete:0xE053,
  ControlRight:0xE01D, AltRight:0xE038, MetaLeft:0xE05B, MetaRight:0xE05C,
};

// Invoked by the client as (kind, data, hotspotX, hotspotY); kind is "default", "hidden" or "url".
function setCursorStyle(kind, data, hotspotX, hotspotY) {
  switch (kind) {
    case 'hidden':
      canvas.style.cursor = 'none';
      break;
    case 'url':
      canvas.style.cursor = data
        ? `url(${data}) ${hotspotX || 0} ${hotspotY || 0}, default`
        : 'default';
      break;
    default:
      canvas.style.cursor = 'default';
  }
}

// The remote is asked for a desktop the size of the viewport, so every pixel is 1:1.
function viewportSize() {
  return new DesktopSize(
    Math.max(640, Math.floor(window.innerWidth)),
    Math.max(480, Math.floor(window.innerHeight)),
  );
}

let resizeTimer = null;
function followWindowSize() {
  clearTimeout(resizeTimer);
  // Debounced: a drag-resize fires continuously and each call is a protocol round trip.
  resizeTimer = setTimeout(() => {
    if (!session) return;
    const size = viewportSize();
    try { session.resize(size.width, size.height); } catch { /* the session may be closing */ }
  }, 250);
}

function sendClipboard() {
  if (!session) return;
  const text = $('clip').value;
  try {
    const data = new ClipboardData();
    if (text) data.addText('text/plain', text);
    session.onClipboardPaste(data);
  } catch (err) {
    say('clipboard: ' + describe(err), true);
  }
}

// Ctrl+Alt+Del never reaches a page as a keystroke; the three scancodes go in one transaction.
function sendCtrlAltDel() {
  if (!session) return;
  const tx = new InputTransaction();
  for (const c of [0x1D, 0x38, 0xE053]) tx.addEvent(DeviceEvent.keyPressed(c));
  for (const c of [0xE053, 0x38, 0x1D]) tx.addEvent(DeviceEvent.keyReleased(c));
  session.applyInputs(tx);
}

function openRail(open) {
  $('rail').classList.toggle('open', open);
  $('rail-toggle').setAttribute('aria-expanded', String(open));
}

$('rail-toggle').addEventListener('click', () => openRail(true));
$('panel-close').addEventListener('click', () => openRail(false));
$('clip-send').addEventListener('click', sendClipboard);
$('clip-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('clip').value); say('copied to this machine'); }
  catch { $('clip').select(); }
});
$('send-cad').addEventListener('click', () => { sendCtrlAltDel(); openRail(false); canvas.focus(); });
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen().catch(() => {});
});
$('panel-disconnect').addEventListener('click', () => endSession());
window.addEventListener('resize', followWindowSize);

// Attached once. Every handler is a no-op without a session.
(function attachInput() {
  const at = e => {
    const r = canvas.getBoundingClientRect();
    return [
      Math.round((e.clientX - r.left) * (canvas.width / r.width)),
      Math.round((e.clientY - r.top) * (canvas.height / r.height)),
    ];
  };
  canvas.addEventListener('mousemove', e => { const [x, y] = at(e); send(DeviceEvent.mouseMove(x, y)); });
  canvas.addEventListener('mousedown', e => { e.preventDefault(); canvas.focus(); send(DeviceEvent.mouseButtonPressed(e.button)); });
  canvas.addEventListener('mouseup', e => { e.preventDefault(); send(DeviceEvent.mouseButtonReleased(e.button)); });
  canvas.addEventListener('contextmenu', e => e.preventDefault());
  canvas.addEventListener('keydown', e => {
    if (!session) return;
    e.preventDefault();
    const c = SCANCODE[e.code];
    if (c !== undefined) send(DeviceEvent.keyPressed(c));
    else if (e.key.length === 1) send(DeviceEvent.unicodePressed(e.key));
  });
  canvas.addEventListener('keyup', e => {
    if (!session) return;
    e.preventDefault();
    const c = SCANCODE[e.code];
    if (c !== undefined) send(DeviceEvent.keyReleased(c));
    else if (e.key.length === 1) send(DeviceEvent.unicodeReleased(e.key));
  });
  canvas.addEventListener('blur', () => { if (session) session.releaseAllInputs(); });
})();

/* ---- file transfer over the clipboard channel (RDPECLIP) ----------------------------------
 *
 *   browser -> remote   initiate_file_copy([{name,size}]) announces the files; the remote asks for
 *                       bytes via file_contents_request_callback, answered with submit_file_contents.
 *   remote -> browser   files_available_callback(files) says what the remote copied; each is pulled
 *                       with request_file_contents and collected from file_contents_response_callback.
 *
 * Callbacks DELIVER camelCase (streamId, isError, dataId, index); invocations TAKE snake_case
 * (stream_id, file_index, is_error, clip_data_id).
 */
const FLAG_SIZE = 0x1;    // the response carries the file's length, not its contents
const FLAG_RANGE = 0x2;   // the response carries the requested byte range
const CHUNK = 1 << 20;    // 1 MiB per range request

let outgoing = [];              // File objects, index-aligned with what initiate_file_copy announced
let remoteFiles = [];           // what the remote has on its clipboard
let nextStream = 1;
const pending = new Map();      // streamId -> resolve/reject for a request we issued

/// Send through `owner`, and only while it is the current session: work started for a session
/// that has since ended must not reach the next one.
function extOn(owner, ident, value) {
  if (!owner || session !== owner) throw new Error('the session this was for has ended');
  return owner.invokeExtension(new Extension(ident, value));
}

function ext(ident, value) {
  return extOn(session, ident, value);
}

function humanSize(n) {
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i];
}

function askRemote(owner, fileIndex, flags, position, size) {
  const streamId = nextStream++;
  return new Promise((resolve, reject) => {
    pending.set(streamId, { resolve, reject });
    try {
      extOn(owner, 'request_file_contents', { stream_id: streamId, file_index: fileIndex, flags, position, size });
    } catch (err) {
      pending.delete(streamId);
      reject(err);
    }
    // Without a timeout a remote that never answers leaves the entry, and the download bar, forever.
    setTimeout(() => {
      if (pending.has(streamId)) {
        pending.delete(streamId);
        reject(new Error('the remote did not answer for file ' + fileIndex));
      }
    }, 30000);
  });
}

/// The remote asks for part of a file this page offered. The answer goes back through the
/// session that asked, and nowhere if that session ended while the file was being read.
async function answerFileRequest(owner, req) {
  const file = outgoing[req.index];
  try {
    if (!file) throw new Error('no file at index ' + req.index);
    let data;
    if (req.flags & FLAG_SIZE) {
      data = new Uint8Array(8);
      new DataView(data.buffer).setBigUint64(0, BigInt(file.size), true);
    } else {
      const slice = file.slice(Number(req.position), Number(req.position) + Number(req.size));
      data = new Uint8Array(await slice.arrayBuffer());
    }
    extOn(owner, 'submit_file_contents', { stream_id: req.streamId, is_error: false, data });
  } catch (err) {
    if (session !== owner) return;   // ended meanwhile: nobody to answer or tell
    // An error reply is required, or the remote's paste hangs rather than failing.
    try { extOn(owner, 'submit_file_contents', { stream_id: req.streamId, is_error: true, data: new Uint8Array() }); } catch { /* session gone */ }
    say('upload failed: ' + describe(err), true);
  }
}

async function downloadRemoteFile(index, li) {
  const owner = session;   // the file is on this session's remote clipboard, and nowhere else
  const meta = remoteFiles[index];
  const bar = document.createElement('progress');
  bar.max = 1; bar.value = 0;
  li.append(bar);
  try {
    let total = Number(meta.size) || 0;
    if (!total) {
      const sized = await askRemote(owner, index, FLAG_SIZE, 0, 8);
      const view = new DataView(sized.buffer, sized.byteOffset, sized.byteLength);
      total = Number(view.getBigUint64(0, true));
    }
    const parts = [];
    for (let at = 0; at < total; at += CHUNK) {
      const want = Math.min(CHUNK, total - at);
      parts.push(await askRemote(owner, index, FLAG_RANGE, at, want));
      bar.value = Math.min(1, (at + want) / total);
    }
    const url = URL.createObjectURL(new Blob(parts));
    const a = document.createElement('a');
    a.href = url;
    a.download = meta.name;
    a.click();
    URL.revokeObjectURL(url);
    say('downloaded ' + meta.name);
  } catch (err) {
    say('download failed: ' + describe(err), true);
  } finally {
    bar.remove();
  }
}

function fileRow(name, size) {
  const li = document.createElement('li');
  const n = document.createElement('span');
  n.className = 'fname';
  n.textContent = name;
  const s = document.createElement('span');
  s.className = 'fsize';
  s.textContent = humanSize(size);
  li.append(n, s);
  return li;
}

function renderIncoming() {
  const list = $('incoming');
  list.innerHTML = '';
  $('incoming-head').hidden = remoteFiles.length === 0;
  remoteFiles.forEach((f, i) => {
    const li = fileRow(f.name, Number(f.size) || 0);
    const get = document.createElement('button');
    get.textContent = 'Download';
    get.addEventListener('click', () => downloadRemoteFile(i, li));
    li.append(get);
    list.append(li);
  });
}

function renderOutgoing() {
  const list = $('outgoing');
  list.innerHTML = '';
  outgoing.forEach(f => list.append(fileRow(f.name, f.size)));
}

function offerFiles(files) {
  if (!session || !files.length) return;
  outgoing = Array.from(files);
  renderOutgoing();
  try {
    ext('initiate_file_copy', outgoing.map(f => ({ name: f.name, size: f.size })));
    say(outgoing.length + ' file(s) on the remote clipboard — paste on the remote');
  } catch (err) {
    say('offering files failed: ' + describe(err), true);
  }
}

const drop = $('drop');
['dragenter', 'dragover'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(e =>
  drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', ev => offerFiles(ev.dataTransfer.files));
$('pick').addEventListener('click', () => $('picker').click());
$('picker').addEventListener('change', ev => offerFiles(ev.target.files));

$('files-note').textContent =
  'Files ride the RDP clipboard channel, so they appear as a paste on the remote rather than as a drive.';

/* ---- opening a server --------------------------------------------------------------------- */

/// Ask for the server's credentials. `prefill` carries a username and domain to start from, and a
/// note when a saved credential was just refused.
function askCredentials(server, prefill = {}) {
  return new Promise(resolve => {
    const dialog = $('signin');
    $('signin-title').textContent = 'Sign in to ' + server.name;
    const note = $('signin-note');
    note.hidden = !prefill.note;
    note.textContent = prefill.note || '';
    $('u').value = prefill.username || '';
    $('p').value = '';
    $('d').value = prefill.domain || '';
    $('save').checked = !!prefill.save;

    const done = () => {
      dialog.removeEventListener('close', done);
      if (dialog.returnValue !== 'go' || !$('u').value) return resolve(null);
      const creds = {
        username: $('u').value.trim(),
        password: $('p').value,
        domain: $('d').value.trim(),
        save: $('save').checked,
      };
      $('p').value = '';   // never leave it sitting in the DOM
      resolve(creds);
    };

    dialog.returnValue = '';
    dialog.addEventListener('close', done);
    dialog.showModal();
    if (!$('u').value) $('u').focus();
    else $('p').focus();
  });
}

// The server being opened or connected. One at a time, from the click until its session ends: a
// second click meanwhile would start a second session over the same page.
let opening = null;

async function openServer(id) {
  const server = servers.get(id);
  if (!server) return;
  if (opening) return say(opening.name + ' is already opening or open');
  opening = server;
  try {
    await connectTo(server, id);
  } finally {
    opening = null;
  }
}

async function connectTo(server, id) {
  let prefill = {};
  // Two rounds at most: a saved credential, then one typed after the saved one was refused.
  for (let round = 0; round < 2; round++) {
    let grant;
    try {
      await clientReady;   // before any ticket is minted, so none ages while the client loads
      grant = await api('POST', '/api/connect', { server: id });
    } catch (err) {
      if (err instanceof SignedOut) return showLogin('Your sign-in has expired. Sign in again.');
      return say('could not open ' + server.name + ': ' + err.message, true);
    }

    const fromSaved = !!grant.credential && round === 0;
    let creds = fromSaved
      ? { username: grant.credential.username, password: grant.credential.password, domain: grant.credential.domain || '', save: false }
      : await askCredentials(server, prefill);
    grant.credential = null;
    if (!creds) { say('cancelled'); return; }

    // A ticket lives 60 seconds and the dialog can take longer, so a fresh one is taken once the
    // credentials are in hand and the client is loaded, immediately before connecting.
    let ticket = grant.ticket;
    if (!fromSaved) {
      try {
        ticket = (await api('POST', '/api/connect', { server: id })).ticket;
      } catch (err) {
        if (err instanceof SignedOut) return showLogin('Your sign-in has expired. Sign in again.');
        return say('could not open ' + server.name + ': ' + err.message, true);
      }
    }

    const outcome = await runSession(server, ticket, creds);
    if (outcome.connected) {
      // The proxy records the end once it sees the socket close, a moment after the client does,
      // so the list is loaded again shortly to pick up the Reconnect marker.
      loadServers();
      setTimeout(loadServers, 1500);
      return;
    }
    // Refused before a desktop appeared. With a saved credential, ask once for a new one.
    if (fromSaved) {
      prefill = {
        username: creds.username,
        domain: creds.domain,
        save: true,
        note: 'The saved credentials did not work. Enter them again; saving replaces the old ones.',
      };
      continue;
    }
    return;
  }
}

/// Connect, run until the session ends, and report whether a desktop was ever reached.
async function runSession(server, ticket, creds) {
  const outcome = { connected: false };
  let mine = null;   // this attempt's session; the page's state is cleared only while it is current
  say('connecting to ' + server.name);
  try {
    await clientReady;
    const builder = new SessionBuilder()
      .proxyAddress(proxyAddress)
      .destination(String(server.id))   // a server ID, never an address
      .authToken(ticket)                // single use, minted for this user and this server
      .username(creds.username)
      .password(creds.password)
      .desktopSize(viewportSize())
      .renderCanvas(canvas)
      .remoteClipboardChangedCallback(data => {
        try {
          for (const item of data.items()) {
            if (String(item.mimeType()).startsWith('text/')) {
              $('clip').value = String(item.value());
              break;
            }
          }
        } catch { /* a clipboard update must never take the session down */ }
      })
      .forceClipboardUpdateCallback(() => sendClipboard())
      .extension(new Extension('files_available_callback', files => {
        remoteFiles = Array.from(files || []);
        renderIncoming();
        if (remoteFiles.length) say(remoteFiles.length + ' file(s) copied on the remote — open the panel to download');
      }))
      .extension(new Extension('file_contents_request_callback', req => answerFileRequest(mine, req)))
      .extension(new Extension('file_contents_response_callback', resp => {
        const waiting = pending.get(resp.streamId);
        if (!waiting) return;
        pending.delete(resp.streamId);
        if (resp.isError) waiting.reject(new Error('the remote reported an error for this file'));
        else waiting.resolve(new Uint8Array(resp.data || []));
      }))
      // Both required: ironrdp-web refuses to connect without every one of username, password,
      // destination, proxyAddress, authToken, renderCanvas, setCursorStyleCallback and
      // setCursorStyleCallbackContext.
      .setCursorStyleCallback(setCursorStyle)
      .setCursorStyleCallbackContext(window)
      .canvasResizedCallback(() => {
        if (!session) return;
        const size = session.desktopSize();
        if (!size) return;
        canvas.width = size.width;
        canvas.height = size.height;
        $('panel-info').textContent = server.name + ' — ' + size.width + '×' + size.height;
      });
    if (creds.domain) builder.serverDomain(creds.domain);

    mine = await builder.connect();
    session = mine;
    outcome.connected = true;

    // Saved only once the server has accepted them, so a mistyped password is never kept.
    if (creds.save) {
      api('PUT', '/api/credentials/' + server.id, {
        username: creds.username, domain: creds.domain || null, password: creds.password,
      }).then(() => say('credentials saved for ' + server.name))
        .catch(err => say('credentials not saved: ' + err.message, true));
    }
    creds.password = '';

    document.body.classList.add('connected');
    $('rail').hidden = false;
    $('panel-target').textContent = server.name;
    $('panel-info').textContent = server.name + ' — ' + canvas.width + '×' + canvas.height;
    canvas.focus();
    say('connected to ' + server.name);

    await mine.run();
    say('disconnected from ' + server.name);
  } catch (err) {
    const text = describe(err);
    say((outcome.connected ? 'session ended: ' : 'could not connect to ' + server.name + ': ') + text, true);
  } finally {
    creds.password = '';
    if (session === mine) {
      document.body.classList.remove('connected');
      $('rail').hidden = true;
      openRail(false);
      session = null;
      // Transfer state belongs to the session.
      outgoing = [];
      remoteFiles = [];
      for (const { reject } of pending.values()) reject(new Error('session ended'));
      pending.clear();
      renderOutgoing();
      renderIncoming();
    }
  }
  return outcome;
}

function endSession() {
  if (session) session.shutdown();
}

showList();
