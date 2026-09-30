// Runs the file-scan notices logic from web/app.js outside a browser: what the poll shows, from
// when, and for which session.
//   node tests/js/notices.mjs            (APP_JS=<path> checks another copy of app.js)
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const path = process.env.APP_JS || fileURLToPath(new URL('../../web/app.js', import.meta.url));
const source = fs.readFileSync(path, 'utf8');

/// A top-level function declaration's text, found by name, braces matched from the `) {` that ends
/// its parameters.
function extract(name) {
  const start = source.search(new RegExp(`^(async )?function ${name}\\(`, 'm'));
  if (start < 0) throw new Error(`app.js has no function ${name}`);
  let depth = 0;
  for (let i = source.indexOf(') {', start) + 2; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

let passed = 0;
let failed = 0;
function check(name, ok, detail = '') {
  if (ok) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (detail ? ': ' + detail : '')); }
}

const FUNCTIONS = ['noticeBaseline', 'watchNotices', 'offerFiles', 'tooLarge', 'fileLimit', 'humanSize', 'ext',
  'extOn'];

/// `replies` answers each request in turn; `tick()` runs one poll.
function sandbox(me, replies) {
  const ctx = {
    me, session: null, outgoing: [], NOTICE_POLL_MS: 2000,
    Extension: class { constructor(ident, value) { this.ident = ident; this.value = value; } },
    said: [], asked: [], tick: null,
    describe: e => String((e && e.message) || e),
    renderOutgoing: () => {},
    Number, Error, Promise, Array, Math,
  };
  ctx.say = (text, bad) => ctx.said.push(bad ? 'BAD ' + text : text);
  ctx.api = async (method, p) => {
    ctx.asked.push(p);
    const r = replies.shift();
    if (!r) throw new Error('no reply');
    if (r.during) r.during(ctx);
    return r;
  };
  ctx.setInterval = fn => { ctx.tick = fn; return 1; };
  ctx.clearInterval = () => { ctx.tick = null; };
  vm.createContext(ctx);
  vm.runInContext(FUNCTIONS.map(extract).join('\n') + '\nconst NOTICE_POLL_MS = 2000;', ctx);
  return ctx;
}

const note = (seq, text, bad = false) => ({ seq, text, bad });

{
  const ctx = sandbox({ scanning: true }, [{ notices: [note(3, 'old')], last: 5 }]);
  const base = await ctx.noticeBaseline();
  check('the baseline is the newest notice before the session', base === 5, String(base));
}

{
  const owner = {};
  const ctx = sandbox({ scanning: true }, [
    { notices: [note(6, 'notes.txt passed the scan; paste on hist-01'), note(7, 'bad.exe not sent', true)], last: 7 },
    { notices: [note(8, 'later')], last: 8 },
  ]);
  ctx.session = owner;
  ctx.watchNotices(owner, 5);
  await ctx.tick();
  check('a poll asks after the baseline', ctx.asked[0] === '/api/me/notices?after=5', ctx.asked[0]);
  check('each notice is shown, bad ones as bad',
    ctx.said.join('|') === 'notes.txt passed the scan; paste on hist-01|BAD bad.exe not sent', ctx.said.join('|'));
  await ctx.tick();
  check('the next poll asks after the newest seen', ctx.asked[1] === '/api/me/notices?after=7', ctx.asked[1]);
}

{
  const owner = {};
  const ctx = sandbox({ scanning: true }, [
    { notices: [note(2, 'from an earlier session')], last: 3 },
    { notices: [note(4, 'new')], last: 4 },
  ]);
  ctx.session = owner;
  ctx.watchNotices(owner, null);
  await ctx.tick();
  check('without a baseline the first poll shows nothing from before', ctx.said.length === 0, ctx.said.join('|'));
  await ctx.tick();
  check('and the polls after it show what is new', ctx.said.join('|') === 'new', ctx.said.join('|'));
}

{
  const owner = {};
  const ctx = sandbox({ scanning: true }, [
    { notices: [note(6, 'late')], last: 6, during: c => { c.session = {}; } },
  ]);
  ctx.session = owner;
  ctx.watchNotices(owner, 5);
  await ctx.tick();
  check('a notice arriving after its session ended is not shown', ctx.said.length === 0, ctx.said.join('|'));
  await ctx.tick();
  check('and another session is not polled for', ctx.asked.length === 1, String(ctx.asked.length));
}

{
  const owner = {};
  const ctx = sandbox({ scanning: true }, []);
  ctx.session = owner;
  const stop = ctx.watchNotices(owner, 0);
  stop();
  check('stopping ends the poll', ctx.tick === null);
}

{
  const sent = [];
  const scanning = sandbox({ scanning: true, max_file_bytes: null }, []);
  scanning.session = { invokeExtension(e) { sent.push(e); } };
  scanning.offerFiles([{ name: 'a.txt', size: 3 }]);
  check('with scanning on, an upload says it is being scanned', /^scanning 1 file/.test(scanning.said[0]),
    scanning.said[0]);
  const plain = sandbox({ scanning: false, max_file_bytes: null }, []);
  plain.session = { invokeExtension(e) { sent.push(e); } };
  plain.offerFiles([{ name: 'a.txt', size: 3 }]);
  check('with scanning off, it says to paste', /paste on the remote$/.test(plain.said[0]), plain.said[0]);
}

console.log(`passed=${passed} failed=${failed}`);
process.exit(failed ? 1 : 0);
