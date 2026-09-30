// Served as a file, not inlined: the proxy's Content-Security-Policy allows `script-src 'self'`.

import init, {
  setup, SessionBuilder, DesktopSize, DeviceEvent, InputTransaction, ClipboardData, Extension,
  IronErrorKind, RotationUnit,
} from './ironrdp_web.js';

const $ = id => document.getElementById(id);
const canvas = $('screen');

// The status line, in the header; during a session the header is hidden, so the same message goes to
// the line at the top of the session panel, and the panel's toggle is marked until it is opened.
let saidAt = 0;
const say = (text, bad = false) => {
  saidAt = Date.now();
  $('status').textContent = text;
  $('status').classList.toggle('bad', bad);
  const line = $('panel-msg');
  line.textContent = text;
  line.classList.toggle('bad', bad);
  line.hidden = false;
  if (document.body.classList.contains('connected') && !$('rail').classList.contains('open')) {
    $('rail-toggle').classList.add('attention');
  }
};
// Ambient state, such as a server count after a refresh: never replaces a message said moments ago.
const note = text => {
  if (Date.now() - saidAt < 8000) return;
  $('status').textContent = text;
  $('status').classList.remove('bad');
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
  $('offline').hidden = view !== 'offline';
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

// Who is signed in, and until when, from the last /api/me or sign-in.
let me = null;
let meAt = 0;

/// Seconds left on the sign-in, counted from what the proxy said and the time since.
function signInRemaining() {
  if (!me || me.remaining_secs == null) return Infinity;
  return me.remaining_secs - (Date.now() - meAt) / 1000;
}

let retryTimer = null;

async function showList() {
  clearTimeout(retryTimer);
  try {
    me = await api('GET', '/api/me');
    meAt = Date.now();
  } catch (err) {
    if (err instanceof SignedOut) return showLogin();
    // Unreachable, restarting or failing: say so where the page would be, and try again.
    show('offline');
    $('offline-why').textContent = describe(err);
    say('could not reach the proxy', true);
    retryTimer = setTimeout(showList, 10000);
    return;
  }
  $('who').textContent = me.display_name || me.username;
  $('admin-link').hidden = !me.is_admin;
  show('list');
  // What was said before the list (signing in, the proxy unreachable) no longer applies.
  saidAt = 0;
  await loadServers();
}

$('retry').addEventListener('click', showList);

$('login-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const go = $('login-go');
  go.disabled = true;
  $('login-error').hidden = true;
  say('signing in');
  try {
    me = await api('POST', '/api/login', { username: $('lu').value, password: $('lp').value });
    meAt = Date.now();
    $('lp').value = '';
    await showList();
  } catch (err) {
    showLogin(err.message);
  } finally {
    go.disabled = false;
  }
});

// A reload after signing out leaves nothing of the last user in the page: no username in the form,
// no clipboard text, no half-typed server password. Workstations here are shared at shift change.
$('signout').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch { /* signed out either way */ }
  location.reload();
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
    if (err instanceof SignedOut) return showLogin('Your sign-in has ended. Sign in again.');
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
  note(total === 1 ? '1 server' : total + ' servers');
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

// What the client's error kinds mean to someone at the keyboard.
const KIND_WORDS = {
  [IronErrorKind.WrongPassword]: 'the server did not accept the password',
  [IronErrorKind.LogonFailure]: 'the server refused the sign-in',
  [IronErrorKind.AccessDenied]: 'the account may not sign in to this server',
  [IronErrorKind.RDCleanPath]: 'the proxy could not open the server',
  [IronErrorKind.ProxyConnect]: 'the proxy could not be reached',
  [IronErrorKind.NegotiationFailure]: 'the server and the client could not agree on a connection',
};
// Windows socket errors the proxy reports for a server it could not reach.
const WSA_WORDS = {
  10051: 'the network to the server is unreachable',
  10053: 'the server dropped the connection',
  10054: 'the server reset the connection',
  10060: 'the server did not answer',
  10061: 'the server refused the connection; is remote desktop running on it?',
  10065: 'the server is unreachable',
  11001: 'the server\'s name is not known to DNS',
};
// TLS alerts the proxy reports for a server certificate it refused.
const TLS_WORDS = {
  42: 'the proxy does not accept the server\'s certificate; the proxy log says why',
  44: 'the server\'s certificate has been revoked',
  45: 'the server\'s certificate has expired or is not yet valid',
  48: 'the server\'s certificate was issued by an authority this proxy does not trust',
};

/// Credential problems, for which asking for the password again can help.
function isCredentialError(err) {
  const kind = errorKind(err);
  return kind === IronErrorKind.WrongPassword || kind === IronErrorKind.LogonFailure
    || kind === IronErrorKind.AccessDenied;
}

// IronError exposes backtrace(), kind() and rdcleanpathDetails() as METHODS, and the detail's fields
// are getters on its prototype, so none of them show up by enumerating the object.
function errorKind(err) {
  try { return err && typeof err.kind === 'function' ? err.kind() : undefined; } catch { return undefined; }
}

function describe(err) {
  if (!err) return 'unknown error';
  const kind = errorKind(err);
  if (kind === undefined) return err.message || String(err);
  const parts = [KIND_WORDS[kind] || 'the connection failed'];
  if (KIND_WORDS[kind] === undefined) {
    // The client names no kind for this one, so its own message is the reason.
    try {
      const first = String(err.backtrace()).split('\n')[0].trim();
      if (first) parts.push(first.slice(0, 200));
    } catch { /* no message */ }
  }
  try {
    const d = typeof err.rdcleanpathDetails === 'function' ? err.rdcleanpathDetails() : null;
    if (d) {
      if (d.wsaErrorCode != null) parts.push(WSA_WORDS[d.wsaErrorCode] || `socket error ${d.wsaErrorCode}`);
      if (d.tlsAlertCode != null) parts.push(TLS_WORDS[d.tlsAlertCode] || `TLS alert ${d.tlsAlertCode}`);
      if (d.httpStatusCode != null) parts.push(`HTTP ${d.httpStatusCode}`);
    }
  } catch { /* the detail is optional */ }
  try { console.error(err.backtrace()); } catch { /* for a support call, not the page */ }
  return parts.join(': ');
}

/* ---- input -------------------------------------------------------------------------------- */

const send = event => {
  if (!session) return;
  const tx = new InputTransaction();
  tx.addEvent(event);
  session.applyInputs(tx);
};

// Keys that never type a character: always sent as their scancode (set 1, by physical position).
const SCANCODE = {
  Escape:0x01, Backspace:0x0E, Tab:0x0F, Enter:0x1C, ControlLeft:0x1D, ShiftLeft:0x2A,
  ShiftRight:0x36, AltLeft:0x38, Space:0x39, CapsLock:0x3A, F1:0x3B, F2:0x3C, F3:0x3D, F4:0x3E,
  F5:0x3F, F6:0x40, F7:0x41, F8:0x42, F9:0x43, F10:0x44, NumLock:0x45, ScrollLock:0x46,
  F11:0x57, F12:0x58, NumpadEnter:0xE01C, NumpadDivide:0xE035, PrintScreen:0xE037,
  Home:0xE047, ArrowUp:0xE048, PageUp:0xE049, ArrowLeft:0xE04B, ArrowRight:0xE04D,
  End:0xE04F, ArrowDown:0xE050, PageDown:0xE051, Insert:0xE052, Delete:0xE053,
  ControlRight:0xE01D, AltRight:0xE038, MetaLeft:0xE05B, MetaRight:0xE05C, ContextMenu:0xE05D,
};

// Keys that type a character, by physical position. Typing sends the character itself, so the
// remote's keyboard layout does not matter; with Ctrl, Alt or the Windows key held, the position
// goes instead, because Windows matches shortcuts on keys, not characters. Numpad keys go by
// position whenever NumLock is off and they act as arrows.
const POSITION = {
  Backquote:0x29, Digit1:0x02, Digit2:0x03, Digit3:0x04, Digit4:0x05, Digit5:0x06, Digit6:0x07,
  Digit7:0x08, Digit8:0x09, Digit9:0x0A, Digit0:0x0B, Minus:0x0C, Equal:0x0D,
  KeyQ:0x10, KeyW:0x11, KeyE:0x12, KeyR:0x13, KeyT:0x14, KeyY:0x15, KeyU:0x16, KeyI:0x17,
  KeyO:0x18, KeyP:0x19, BracketLeft:0x1A, BracketRight:0x1B, Backslash:0x2B,
  KeyA:0x1E, KeyS:0x1F, KeyD:0x20, KeyF:0x21, KeyG:0x22, KeyH:0x23, KeyJ:0x24, KeyK:0x25,
  KeyL:0x26, Semicolon:0x27, Quote:0x28, IntlBackslash:0x56,
  KeyZ:0x2C, KeyX:0x2D, KeyC:0x2E, KeyV:0x2F, KeyB:0x30, KeyN:0x31, KeyM:0x32, Comma:0x33,
  Period:0x34, Slash:0x35,
  NumpadMultiply:0x37, Numpad7:0x47, Numpad8:0x48, Numpad9:0x49, NumpadSubtract:0x4A,
  Numpad4:0x4B, Numpad5:0x4C, Numpad6:0x4D, NumpadAdd:0x4E, Numpad1:0x4F, Numpad2:0x50,
  Numpad3:0x51, Numpad0:0x52, NumpadDecimal:0x53,
};

/// How a key goes to the remote: ['scan', code], ['char', character], or null for a key with no
/// meaning there, which is dropped rather than guessed at.
function keyRoute(e) {
  if (SCANCODE[e.code] !== undefined) return ['scan', SCANCODE[e.code]];
  const altGr = typeof e.getModifierState === 'function' && e.getModifierState('AltGraph');
  const shortcut = (e.ctrlKey || e.altKey || e.metaKey) && !altGr;
  // A dead key composes the next character locally, and that character goes across as text.
  if (!shortcut && e.key === 'Dead') return null;
  if ((shortcut || e.key.length !== 1) && POSITION[e.code] !== undefined) return ['scan', POSITION[e.code]];
  if (e.key.length === 1) return ['char', e.key];
  return null;
}

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

// A session starts at the viewport's CSS size, which every server honours. Once it runs, the remote
// is asked for the viewport in device pixels with this display's scale, so at 125 % or 150 % every
// remote pixel is one screen pixel and text keeps the size the user expects. The canvas has no size
// of its own in CSS: it shows its bitmap at natural size, capped to the viewport (app.css), so a
// bitmap in device pixels lands one to one, and a remote resize needs no callback.
const scale = () => Math.max(1, window.devicePixelRatio || 1);

function cssViewportSize() {
  return new DesktopSize(Math.max(640, window.innerWidth), Math.max(480, window.innerHeight));
}

/// Ask the remote for the viewport in device pixels and this display's scale, 100 included, so a
/// window moved from a scaled display back to an unscaled one is set back too.
function fitRemote() {
  if (!session) return;
  const factor = Math.round(scale() * 100);
  try {
    session.resize(
      Math.max(640, Math.floor(window.innerWidth * scale())),
      Math.max(480, Math.floor(window.innerHeight * scale())),
      factor,
    );
  } catch { /* the session may be closing */ }
}

let resizeTimer = null;
let fitTimers = [];
function followWindowSize() {
  clearTimeout(resizeTimer);
  // Debounced: a drag-resize fires continuously and each call is a protocol round trip.
  resizeTimer = setTimeout(fitRemote, 250);
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
  if (open) {
    $('rail-toggle').classList.remove('attention');
    $('panel-info').textContent = $('panel-target').textContent + ' — ' + canvas.width + '×' + canvas.height;
  }
}

$('rail-toggle').addEventListener('click', () => openRail(true));
// Focus goes back to the desktop, or the next keystrokes land on a hidden button.
$('panel-close').addEventListener('click', () => { openRail(false); canvas.focus(); });
$('clip-send').addEventListener('click', sendClipboard);
$('clip-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('clip').value); say('copied to this machine'); }
  catch { $('clip').select(); }
});
$('send-cad').addEventListener('click', () => { sendCtrlAltDel(); openRail(false); canvas.focus(); });
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen().catch(() => {});
  // Or the next keystrokes land on this button, and Space turns fullscreen off again.
  openRail(false);
  canvas.focus();
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

  // A key is released the way it was pressed: Ctrl let go before C must not turn C's release into a
  // character the remote never saw pressed.
  const down = new Map();   // e.code -> route
  let syncLocks = true;     // Caps, Num and Scroll Lock are read from the next key after focus
  canvas.addEventListener('keydown', e => {
    if (!session) return;
    e.preventDefault();
    if (syncLocks && typeof e.getModifierState === 'function') {
      syncLocks = false;
      try {
        session.synchronizeLockKeys(e.getModifierState('ScrollLock'), e.getModifierState('NumLock'),
          e.getModifierState('CapsLock'), false);
      } catch { /* an older server ignores it */ }
    }
    const route = down.get(e.code) || keyRoute(e);
    if (!route) return;
    down.set(e.code, route);
    send(route[0] === 'scan' ? DeviceEvent.keyPressed(route[1]) : DeviceEvent.unicodePressed(route[1]));
  });
  canvas.addEventListener('keyup', e => {
    if (!session) return;
    e.preventDefault();
    const route = down.get(e.code) || keyRoute(e);
    down.delete(e.code);
    if (!route) return;
    send(route[0] === 'scan' ? DeviceEvent.keyReleased(route[1]) : DeviceEvent.unicodeReleased(route[1]));
  });
  canvas.addEventListener('focus', () => { syncLocks = true; });
  canvas.addEventListener('blur', () => {
    down.clear();
    if (session) session.releaseAllInputs();
  });

  // The wheel scrolls the remote. The browser's delta counts down the page; the remote's wheel
  // counts away from the user, so the vertical sign flips.
  canvas.addEventListener('wheel', e => {
    if (!session) return;
    e.preventDefault();
    const unit = e.deltaMode === 1 ? RotationUnit.Line : e.deltaMode === 2 ? RotationUnit.Page : RotationUnit.Pixel;
    const tx = new InputTransaction();
    if (e.deltaY) tx.addEvent(DeviceEvent.wheelRotations(true, -Math.round(e.deltaY), unit));
    if (e.deltaX) tx.addEvent(DeviceEvent.wheelRotations(false, Math.round(e.deltaX), unit));
    session.applyInputs(tx);
  }, { passive: false });

  // A file dropped anywhere on the page goes to the remote clipboard instead of replacing the page,
  // which would end the session.
  for (const type of ['dragover', 'drop']) {
    document.addEventListener(type, e => { if (session) e.preventDefault(); });
  }
  canvas.addEventListener('drop', e => {
    if (!session || !e.dataTransfer || !e.dataTransfer.files.length) return;
    offerFiles(e.dataTransfer.files);
    openRail(true);
  });
})();

// Leaving the page ends the session; ask first.
window.addEventListener('beforeunload', e => {
  if (!session) return;
  e.preventDefault();
  e.returnValue = '';
});

// In fullscreen, Chromium lets the page take the Windows key, Alt+Tab and Escape for the remote.
document.addEventListener('fullscreenchange', () => {
  if (!navigator.keyboard || typeof navigator.keyboard.lock !== 'function') return;
  if (document.fullscreenElement) navigator.keyboard.lock().catch(() => {});
  else navigator.keyboard.unlock();
});

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
    const limit = fileLimit();
    if (tooLarge([{ size: total }], limit).length) {
      throw new Error(meta.name + ' is larger than the ' + humanSize(limit) + ' limit');
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

/// The largest file sent or fetched, in bytes, or null for no limit (Settings tab).
function fileLimit() {
  return me && Number.isFinite(me.max_file_bytes) ? me.max_file_bytes : null;
}

/// The files larger than `limit`; none when there is no limit.
function tooLarge(files, limit) {
  return limit === null ? [] : files.filter(f => Number(f.size) > limit);
}

function renderIncoming() {
  const list = $('incoming');
  list.innerHTML = '';
  $('incoming-head').hidden = remoteFiles.length === 0;
  remoteFiles.forEach((f, i) => {
    const li = fileRow(f.name, Number(f.size) || 0);
    const limit = fileLimit();
    if (tooLarge([f], limit).length) {
      const too = document.createElement('span');
      too.className = 'fsize';
      too.textContent = 'over the ' + humanSize(limit) + ' limit';
      li.append(too);
    } else {
      const get = document.createElement('button');
      get.textContent = 'Download';
      get.addEventListener('click', () => downloadRemoteFile(i, li));
      li.append(get);
    }
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
  const limit = fileLimit();
  const over = tooLarge(Array.from(files), limit);
  if (over.length) {
    say('nothing sent: ' + over.map(f => f.name).join(', ') + ' larger than the ' + humanSize(limit) + ' limit', true);
    return;
  }
  outgoing = Array.from(files);
  renderOutgoing();
  try {
    ext('initiate_file_copy', outgoing.map(f => ({ name: f.name, size: f.size })));
    say(me && me.scanning
      ? 'scanning ' + outgoing.length + ' file(s); paste on the remote once they pass'
      : outgoing.length + ' file(s) on the remote clipboard — paste on the remote');
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

function filesNote() {
  $('files-note').textContent =
    'Files ride the RDP clipboard channel, so they appear as a paste on the remote rather than as a drive.' +
    (me && me.scanning ? ' Every file is scanned for malware on the way, in both directions.' : '');
}
filesNote();

/* ---- the file scan's decisions -------------------------------------------------------------- */

const NOTICE_POLL_MS = 2000;

/// The newest notice number before a session opens, so none from an earlier session is shown;
/// null when unknown, and the first poll then only takes it.
async function noticeBaseline() {
  try { return (await api('GET', '/api/me/notices?after=0')).last; } catch { return null; }
}

/// Shows what the proxy's file scan decided while `owner` is the session. Returns the stop.
function watchNotices(owner, after) {
  let busy = false;
  const timer = setInterval(async () => {
    if (busy || session !== owner) return;
    busy = true;
    try {
      const r = await api('GET', '/api/me/notices?after=' + (after ?? 0));
      const show = after !== null && session === owner;
      after = r.last;
      if (show) for (const n of r.notices) say(n.text, n.bad);
    } catch { /* a missed poll is retried; the sign-in's end is handled where it happens */ }
    finally { busy = false; }
  }, NOTICE_POLL_MS);
  return () => clearInterval(timer);
}

/* ---- opening a server --------------------------------------------------------------------- */

/// The domain the server sign-in starts with: the one just tried, else the server's default.
function startDomain(prefill, server) {
  return prefill.domain || server.domain || '';
}

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
    $('d').value = startDomain(prefill, server);
    $('save').checked = !!prefill.save;

    const done = () => {
      dialog.removeEventListener('close', done);
      const password = $('p').value;
      $('p').value = '';   // never left sitting in the DOM, however the dialog closed
      if (dialog.returnValue !== 'go' || !$('u').value) return resolve(null);
      resolve({
        username: $('u').value.trim(),
        password,
        domain: $('d').value.trim(),
        save: $('save').checked,
      });
    };

    dialog.returnValue = '';
    dialog.addEventListener('close', done);
    dialog.showModal();
    if (!$('u').value) $('u').focus();
    else $('p').focus();
  });
}

// Cancel is an ordinary button, so Enter in the dialog submits it with Connect.
$('signin-cancel').addEventListener('click', () => $('signin').close('cancel'));

// A session lives only as long as the sign-in it opens under. With less left than the renewal point
// on the Settings tab, the page asks for the password before connecting, so the desktop is not cut
// mid-shift. 0 never asks.
function renewBelow() {
  return me && Number.isFinite(me.renew_below_secs) ? me.renew_below_secs : 18 * 60 * 60;
}

/// "3 hours", or minutes under the last hour.
function lasting(secs) {
  const plural = (n, unit) => n + ' ' + unit + (n === 1 ? '' : 's');
  const minutes = Math.max(1, Math.ceil(secs / 60));
  if (minutes >= 60) return plural(Math.floor(minutes / 60), 'hour');
  return plural(minutes, 'minute');
}

/// Ask for the password to renew the sign-in. True once renewed, false to go on without.
function renewSignIn() {
  return new Promise(resolve => {
    const dialog = $('renew');
    $('renew-left').textContent = lasting(signInRemaining());
    $('renew-error').hidden = true;
    $('renew-pass').value = '';
    const submit = async ev => {
      ev.preventDefault();
      $('renew-go').disabled = true;
      try {
        me = await api('POST', '/api/login', { username: me.username, password: $('renew-pass').value });
        meAt = Date.now();
        finish(true);
      } catch (err) {
        $('renew-error').textContent = err.message;
        $('renew-error').hidden = false;
      } finally {
        $('renew-go').disabled = false;
        $('renew-pass').value = '';
      }
    };
    const skip = () => finish(false);
    const finish = renewed => {
      $('renew-form').removeEventListener('submit', submit);
      $('renew-skip').removeEventListener('click', skip);
      dialog.removeEventListener('cancel', skip);
      // A directory password typed and then skipped is never left sitting in the page.
      $('renew-pass').value = '';
      if (dialog.open) dialog.close();
      resolve(renewed);
    };
    $('renew-form').addEventListener('submit', submit);
    $('renew-skip').addEventListener('click', skip);
    dialog.addEventListener('cancel', skip);
    dialog.showModal();
    $('renew-pass').focus();
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
  say('opening ' + server.name);   // the client may still be loading; say so rather than nothing
  try {
    if (signInRemaining() < renewBelow()) await renewSignIn();
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
    // Refused before a desktop appeared. A saved credential the server refused is asked for once
    // more; a server that could not be reached is not a password problem, and is only reported.
    if (fromSaved && outcome.credentials) {
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
  // connected: a desktop was reached. credentials: refused for the credentials, not the network.
  const outcome = { connected: false, credentials: false };
  let mine = null;   // this attempt's session; the page's state is cleared only while it is current
  let stopNotices = () => {};
  say('connecting to ' + server.name);
  try {
    await clientReady;
    filesNote();
    // Taken before connecting: a clipboard the remote holds at connect is scanned at once.
    const baseline = me && me.scanning ? await noticeBaseline() : undefined;
    const builder = new SessionBuilder()
      .proxyAddress(proxyAddress)
      .destination(String(server.id))   // a server ID, never an address
      .authToken(ticket)                // single use, minted for this user and this server
      .username(creds.username)
      .password(creds.password)
      .desktopSize(cssViewportSize())
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
      .setCursorStyleCallbackContext(window);
    if (creds.domain) builder.serverDomain(creds.domain);

    mine = await builder.connect();
    session = mine;
    outcome.connected = true;
    if (baseline !== undefined) stopNotices = watchNotices(mine, baseline);
    // A resize sent before the display channel is open is dropped, so the scale waits until the
    // session has run a moment, and is asked once more if the bitmap has not changed by then.
    if (scale() !== 1) {
      const asked = canvas.width;
      fitTimers.push(setTimeout(() => { if (session === mine) fitRemote(); }, 2000));
      fitTimers.push(setTimeout(() => { if (session === mine && canvas.width === asked) fitRemote(); }, 6000));
    }

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
    canvas.focus();
    say('connected to ' + server.name);

    const info = await mine.run();
    let why = '';
    try { why = info && typeof info.reason === 'function' ? String(info.reason() || '') : ''; } catch { /* optional */ }
    say('disconnected from ' + server.name + (why ? ': ' + why : ''));
  } catch (err) {
    outcome.credentials = !outcome.connected && isCredentialError(err);
    const text = describe(err);
    say((outcome.connected ? 'session with ' + server.name + ' ended: ' : 'could not connect to ' + server.name + ': ') + text, true);
  } finally {
    creds.password = '';
    stopNotices();
    if (session === mine) {
      for (const t of fitTimers.splice(0)) clearTimeout(t);
      document.body.classList.remove('connected');
      $('rail').hidden = true;
      openRail(false);
      $('rail-toggle').classList.remove('attention');
      // Fullscreen and its keyboard lock belong to the session.
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      else if (navigator.keyboard && typeof navigator.keyboard.unlock === 'function') navigator.keyboard.unlock();
      session = null;
      // Transfer state and clipboard text belong to the session.
      $('clip').value = '';
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
