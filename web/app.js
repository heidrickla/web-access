// Served as a file, not inlined. The proxy's Content-Security-Policy allows `script-src 'self'`,
// which permits this and forbids an inline <script>. An inline module block is dropped without a
// console error visible on the page, so the only symptom is a status that never leaves "loading".
// Measured 2026-09-23.

import init, { setup, SessionBuilder, DesktopSize, DeviceEvent, InputTransaction, ClipboardData, Extension }
  from './ironrdp_web.js';

const $ = id => document.getElementById(id);
const canvas = $('screen');
const say = (text, bad = false) => {
  $('status').textContent = text;
  $('status').classList.toggle('bad', bad);
};

// Same origin as the page that was served, so there is nothing to configure and no way to point the
// client at a different proxy.
const proxyAddress = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';

let token = '';
let session = null;

try {
  say('loading the client');
  await init();
  setup('info');
} catch (err) {
  say('the RDP client failed to load: ' + describe(err), true);
  throw err;
}

// The launcher's contents come from the proxy's own allowlist, filtered by the same predicate the
// connection will use. Nothing is typed in: the systems are listed because the config lists them,
// and the proxy token arrives with them.
try {
  const res = await fetch('/api/targets', { cache: 'no-store' });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const data = await res.json();
  token = data.token;
  render(data.targets || []);
} catch (err) {
  say('could not load the system list: ' + describe(err), true);
}

function render(targets) {
  const tiles = $('tiles');
  tiles.innerHTML = '';
  if (!targets.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = "No systems. The proxy's allowlist is empty, or no policy grants this identity a tag that any target carries. Both are edited in config.toml.";
    tiles.append(p);
    say('no systems available');
    return;
  }
  for (const t of targets) {
    const b = document.createElement('button');
    b.className = 'tile';
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = t.id;
    const tags = document.createElement('div');
    tags.className = 'tags';
    for (const tag of t.tags || []) {
      const chip = document.createElement('span');
      chip.className = 'tag';
      chip.textContent = tag;   // textContent, never innerHTML: these come from a config file
      tags.append(chip);
    }
    b.append(name, tags);
    b.addEventListener('click', () => connect(t.id));
    tiles.append(b);
  }
  say(targets.length + (targets.length === 1 ? ' system' : ' systems'));
}

// IronError exposes backtrace(), kind() and rdcleanpathDetails() as METHODS. Reading `err.backtrace`
// without calling it is truthy — it is a function — so stringifying it printed the function's own
// source code instead of the failure. Measured 2026-09-23, and the reason a real error was invisible.
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
  return parts.length ? parts.join(' — ') : String(err);
}

const send = event => {
  if (!session) return;
  const tx = new InputTransaction();
  tx.addEvent(event);
  session.applyInputs(tx);
};

// Printable keys go through unicode, which avoids a full PS/2 set-1 table. The rest need scancodes,
// so the essential ones are mapped; anything outside both is dropped rather than guessed at, which
// shows up as a dead key rather than as a wrong character.
const SCANCODE = {
  Escape:0x01, Backspace:0x0E, Tab:0x0F, Enter:0x1C, ControlLeft:0x1D, ShiftLeft:0x2A,
  ShiftRight:0x36, AltLeft:0x38, Space:0x39, CapsLock:0x3A, F1:0x3B, F2:0x3C, F3:0x3D, F4:0x3E,
  F5:0x3F, F6:0x40, F7:0x41, F8:0x42, F9:0x43, F10:0x44, F11:0x57, F12:0x58,
  Home:0xE047, ArrowUp:0xE048, PageUp:0xE049, ArrowLeft:0xE04B, ArrowRight:0xE04D,
  End:0xE04F, ArrowDown:0xE050, PageDown:0xE051, Insert:0xE052, Delete:0xE053,
  ControlRight:0xE01D, AltRight:0xE038, MetaLeft:0xE05B, MetaRight:0xE05C,
};

// Invoked by the client as (kind, data, hotspotX, hotspotY), where kind is "default", "hidden" or
// "url" and data is a data-URL for the cursor image. Read from ironrdp-web's session.rs.
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

// The remote is asked for a desktop the size of the browser viewport, so every pixel is 1:1 and
// nothing is scaled. Scaling is what makes remote text fuzzy; resizing the desktop does not.
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

// Ctrl+Alt+Del cannot arrive as a keystroke: the browser never delivers it. Pressing and releasing
// the three scancodes in one transaction is the only way to send it.
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

/* ---- file transfer over the clipboard channel (RDPECLIP) ------------------
 *
 * Two directions, both routed through invokeExtension because the surface is protocol-specific:
 *
 *   browser -> remote   initiate_file_copy([{name,size}])  announces the files. The remote then asks
 *                       for bytes via file_contents_request_callback, answered with
 *                       submit_file_contents.
 *   remote -> browser   files_available_callback(files) says what the remote copied. We pull each
 *                       one with request_file_contents and collect file_contents_response_callback.
 *
 * NOTE THE CASE ASYMMETRY, which is easy to get wrong: callbacks DELIVER camelCase (streamId,
 * isError, dataId, index) and invocations TAKE snake_case (stream_id, file_index, is_error,
 * clip_data_id). Read from ironrdp-web's clipboard.rs and session.rs.
 */
const FLAG_SIZE = 0x1;    // the response carries the file's length, not its contents
const FLAG_RANGE = 0x2;   // the response carries the requested byte range
const CHUNK = 1 << 20;    // 1 MiB per range request

let outgoing = [];              // File objects, index-aligned with what initiate_file_copy announced
let remoteFiles = [];           // what the remote has on its clipboard
let nextStream = 1;
const pending = new Map();      // streamId -> resolve/reject for a request we issued

function ext(ident, value) {
  if (!session) throw new Error('no session');
  return session.invokeExtension(new Extension(ident, value));
}

function humanSize(n) {
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i];
}

/// Ask the remote for one slice, resolving when its response arrives.
function askRemote(fileIndex, flags, position, size) {
  const streamId = nextStream++;
  return new Promise((resolve, reject) => {
    pending.set(streamId, { resolve, reject });
    try {
      ext('request_file_contents', {
        stream_id: streamId,
        file_index: fileIndex,
        flags,
        position,
        size,
      });
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

async function downloadRemoteFile(index, li) {
  const meta = remoteFiles[index];
  const bar = document.createElement('progress');
  bar.max = 1; bar.value = 0;
  li.append(bar);
  try {
    // The size the clipboard advertised is not always present, so ask for it explicitly first.
    let total = Number(meta.size) || 0;
    if (!total) {
      const sized = await askRemote(index, FLAG_SIZE, 0, 8);
      // The SIZE response carries a little-endian 64-bit length.
      const view = new DataView(sized.buffer, sized.byteOffset, sized.byteLength);
      total = Number(view.getBigUint64(0, true));
    }

    const parts = [];
    for (let at = 0; at < total; at += CHUNK) {
      const want = Math.min(CHUNK, total - at);
      parts.push(await askRemote(index, FLAG_RANGE, at, want));
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

function renderIncoming() {
  const list = $('incoming');
  list.innerHTML = '';
  $('incoming-head').hidden = remoteFiles.length === 0;
  remoteFiles.forEach((f, i) => {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'fname';
    name.textContent = f.name;
    const size = document.createElement('span');
    size.className = 'fsize';
    size.textContent = humanSize(Number(f.size) || 0);
    const get = document.createElement('button');
    get.textContent = 'Download';
    get.addEventListener('click', () => downloadRemoteFile(i, li));
    li.append(name, size, get);
    list.append(li);
  });
}

function renderOutgoing() {
  const list = $('outgoing');
  list.innerHTML = '';
  outgoing.forEach(f => {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'fname';
    name.textContent = f.name;
    const size = document.createElement('span');
    size.className = 'fsize';
    size.textContent = humanSize(f.size);
    li.append(name, size);
    list.append(li);
  });
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

function attachInput() {
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
    e.preventDefault();
    const c = SCANCODE[e.code];
    if (c !== undefined) send(DeviceEvent.keyPressed(c));
    else if (e.key.length === 1) send(DeviceEvent.unicodePressed(e.key));
  });
  canvas.addEventListener('keyup', e => {
    e.preventDefault();
    const c = SCANCODE[e.code];
    if (c !== undefined) send(DeviceEvent.keyReleased(c));
    else if (e.key.length === 1) send(DeviceEvent.unicodeReleased(e.key));
  });
  canvas.addEventListener('blur', () => { if (session) session.releaseAllInputs(); });
}

/// Ask for Windows credentials, after a system has been chosen.
///
/// IronRDP requires a username: connecting without one fails with "username missing", so there is no
/// variant of this where the target's own login screen appears instead. The username is remembered
/// per target because retyping it every time is the annoyance; THE PASSWORD IS NEVER STORED.
function askCredentials(targetId) {
  return new Promise(resolve => {
    const dialog = $('signin');
    $('signin-title').textContent = 'Sign in to ' + targetId;

    const remembered = localStorage.getItem('user:' + targetId) || '';
    $('u').value = remembered;
    $('p').value = '';
    $('d').value = localStorage.getItem('domain:' + targetId) || '';

    const done = () => {
      dialog.removeEventListener('close', done);
      if (dialog.returnValue !== 'go' || !$('u').value) return resolve(null);
      const creds = { username: $('u').value, password: $('p').value, domain: $('d').value.trim() };
      localStorage.setItem('user:' + targetId, creds.username);
      if (creds.domain) localStorage.setItem('domain:' + targetId, creds.domain);
      else localStorage.removeItem('domain:' + targetId);
      $('p').value = '';
      resolve(creds);
    };

    dialog.addEventListener('close', done);
    dialog.showModal();
    // Focus whichever field still needs filling in.
    ($('u').value ? $('p') : $('u')).focus();
  });
}

async function connect(targetId) {
  const creds = await askCredentials(targetId);
  if (!creds) { say('cancelled'); return; }

  say('connecting to ' + targetId);
  try {
    // Pass-through: these go to the target inside the RDP stream, which the proxy does not decode.
    // The proxy neither sees nor stores them.
    const builder = new SessionBuilder()
      .proxyAddress(proxyAddress)
      .destination(targetId)   // a TARGET ID, never an address
      .authToken(token)        // minted by the proxy when it served this page
      .username(creds.username)
      .password(creds.password)
      .desktopSize(viewportSize())
      .renderCanvas(canvas)
      // Text clipboard, both directions. Files go through invokeExtension and are not wired yet.
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
      // File transfer callbacks are registered through extension(), not as builder methods.
      .extension(new Extension('files_available_callback', files => {
        remoteFiles = Array.from(files || []);
        renderIncoming();
        if (remoteFiles.length) say(remoteFiles.length + ' file(s) copied on the remote — open the panel to download');
      }))
      .extension(new Extension('file_contents_request_callback', async req => {
        // The remote is pasting our files and wants bytes.
        const file = outgoing[req.index];
        try {
          if (!file) throw new Error('no file at index ' + req.index);
          let data;
          if (req.flags & FLAG_SIZE) {
            // The SIZE reply is the length as a little-endian 64-bit value, not file content.
            data = new Uint8Array(8);
            new DataView(data.buffer).setBigUint64(0, BigInt(file.size), true);
          } else {
            const slice = file.slice(Number(req.position), Number(req.position) + Number(req.size));
            data = new Uint8Array(await slice.arrayBuffer());
          }
          ext('submit_file_contents', { stream_id: req.streamId, is_error: false, data });
        } catch (err) {
          // An error reply is required, or the remote's paste hangs rather than failing.
          try { ext('submit_file_contents', { stream_id: req.streamId, is_error: true, data: new Uint8Array() }); } catch { /* session gone */ }
          say('upload failed: ' + describe(err), true);
        }
      }))
      .extension(new Extension('file_contents_response_callback', resp => {
        const waiting = pending.get(resp.streamId);
        if (!waiting) return;
        pending.delete(resp.streamId);
        if (resp.isError) waiting.reject(new Error('the remote reported an error for this file'));
        else waiting.resolve(new Uint8Array(resp.data || []));
      }))
      // REQUIRED, both of them. ironrdp-web refuses to connect without every one of username,
      // password, destination, proxyAddress, authToken, renderCanvas, setCursorStyleCallback and
      // setCursorStyleCallbackContext. Read off session.rs rather than discovered one failure at a
      // time, which is how the first two were found.
      .setCursorStyleCallback(setCursorStyle)
      .setCursorStyleCallbackContext(window)
      // Optional and worth having: the remote decides the desktop size, so follow it rather than
      // leaving the canvas at whatever it was created with.
      .canvasResizedCallback(() => {
        if (!session) return;
        const size = session.desktopSize();
        if (!size) return;
        canvas.width = size.width;
        canvas.height = size.height;
        $('panel-info').textContent = targetId + ' — ' + size.width + '×' + size.height;
      });
    if (creds.domain) builder.serverDomain(creds.domain);

    session = await builder.connect();

    document.body.classList.add('connected');
    $('back').hidden = false;
    $('rail').hidden = false;
    $('panel-target').textContent = targetId;
    $('panel-info').textContent = targetId + ' — ' + canvas.width + '×' + canvas.height;
    attachInput();
    canvas.focus();
    say('connected to ' + targetId);

    await session.run();
    say('session ended');
  } catch (err) {
    const text = describe(err);
    // A target with NLA enabled refuses before any screen is drawn, because CredSSP wants the
    // credentials up front. Say so plainly rather than showing a bare protocol error.
    if (/credssp|logon|authentic|password|credential/i.test(text)) {
      say('sign-in refused by ' + targetId + ': ' + text, true);
    } else {
      say('failed: ' + text, true);
    }
  } finally {
    document.body.classList.remove('connected');
    $('back').hidden = true;
    $('rail').hidden = true;
    openRail(false);
    session = null;
    // Transfer state belongs to the session. Leaving it would show the last session's files and let
    // a stale streamId resolve against a new one.
    outgoing = [];
    remoteFiles = [];
    for (const { reject } of pending.values()) reject(new Error('session ended'));
    pending.clear();
    renderOutgoing();
    renderIncoming();
  }
}

function endSession() {
  if (session) session.shutdown();
}

$('back').addEventListener('click', () => {
  endSession();
  say('disconnecting');
});
