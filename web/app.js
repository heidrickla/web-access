// Served as a file, not inlined. The proxy's Content-Security-Policy allows `script-src 'self'`,
// which permits this and forbids an inline <script>. An inline module block is dropped without a
// console error visible on the page, so the only symptom is a status that never leaves "loading".
// Measured 2026-09-23.

import init, { setup, SessionBuilder, DesktopSize, DeviceEvent, InputTransaction }
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

async function connect(targetId) {
  say('connecting to ' + targetId);
  try {
    // NO CREDENTIALS ARE SUPPLIED HERE ON PURPOSE. Pass-through means the Windows account belongs to
    // the session, not to this page: with NLA off the target's own login screen appears in the
    // canvas, which is where it should be typed.
    session = await new SessionBuilder()
      .proxyAddress(proxyAddress)
      .destination(targetId)   // a TARGET ID, never an address
      .authToken(token)        // minted by the proxy when it served this page
      .desktopSize(new DesktopSize(canvas.width, canvas.height))
      .renderCanvas(canvas)
      .connect();

    document.body.classList.add('connected');
    $('back').hidden = false;
    attachInput();
    canvas.focus();
    say('connected to ' + targetId);

    await session.run();
    say('session ended');
  } catch (err) {
    const text = describe(err);
    // A target with NLA enabled refuses before any screen is drawn, because CredSSP wants the
    // credentials up front. Say so plainly rather than showing a bare protocol error.
    if (/credssp|nla|negotiat/i.test(text)) {
      say(targetId + ' requires Network Level Authentication, which needs credentials before the session starts. Turn NLA off on that host, or this page needs a credential prompt adding.', true);
    } else {
      say('failed: ' + text, true);
    }
  } finally {
    document.body.classList.remove('connected');
    $('back').hidden = true;
    session = null;
  }
}

$('back').addEventListener('click', () => {
  if (session) session.shutdown();
  document.body.classList.remove('connected');
  $('back').hidden = true;
  session = null;
  say('disconnected');
});
