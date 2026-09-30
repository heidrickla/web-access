// Runs the Settings-tab logic from web/app.js outside a browser: the renewal point, the file-size
// limit both ways, and the server's default domain in the server sign-in.
//   node tests/js/settings.mjs            (APP_JS=<path> checks another copy of app.js)
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

const FUNCTIONS = ['renewBelow', 'fileLimit', 'tooLarge', 'startDomain', 'humanSize', 'offerFiles',
  'downloadRemoteFile', 'askRemote', 'extOn', 'ext'];

function sandbox(me) {
  const element = () => ({ append() {}, remove() {}, max: 0, value: 0 });
  const ctx = {
    me, session: null, outgoing: [], remoteFiles: [], pending: new Map(), nextStream: 1,
    FLAG_SIZE: 0x1, FLAG_RANGE: 0x2, CHUNK: 1 << 20,
    Extension: class { constructor(ident, value) { this.ident = ident; this.value = value; } },
    said: [],
    describe: e => String((e && e.message) || e),
    renderOutgoing: () => {},
    setTimeout: () => 0,
    document: { createElement: element },
    Uint8Array, DataView, BigInt, Number, Error, Promise, Map, Array, Math,
  };
  ctx.say = text => ctx.said.push(text);
  vm.createContext(ctx);
  vm.runInContext(FUNCTIONS.map(extract).join('\n'), ctx);
  return ctx;
}

function standIn() {
  const sent = [];
  return { sent, invokeExtension(e) { sent.push(e); } };
}

const MB = 1024 * 1024;

{
  const ctx = sandbox({ renew_below_secs: 0 });
  check('a renewal point of 0 never asks for the password', ctx.renewBelow() === 0, String(ctx.renewBelow()));
  const set = sandbox({ renew_below_secs: 7200 });
  check('the renewal point comes from the Settings tab', set.renewBelow() === 7200, String(set.renewBelow()));
  const none = sandbox(null);
  check('before sign-in the renewal point is 18 hours', none.renewBelow() === 18 * 3600, String(none.renewBelow()));
}

{
  const ctx = sandbox({ max_file_bytes: 10 * MB });
  const over = ctx.tooLarge([{ name: 'a', size: 10 * MB }, { name: 'b', size: 10 * MB + 1 }], ctx.fileLimit());
  check('a file at the limit passes and one byte over does not', over.map(f => f.name).join() === 'b',
    JSON.stringify(over));
  const open = sandbox({ max_file_bytes: null });
  check('with no limit no file is too large', open.tooLarge([{ size: 1e12 }], open.fileLimit()).length === 0);
}

{
  const ctx = sandbox({ max_file_bytes: 10 * MB });
  const a = standIn();
  ctx.session = a;
  ctx.offerFiles([{ name: 'small.txt', size: 100 }, { name: 'big.iso', size: 50 * MB }]);
  check('an upload with a file over the limit sends nothing', a.sent.length === 0,
    JSON.stringify(a.sent.map(e => e.value)));
  check('an upload names the files over the limit', ctx.said.some(s => s.includes('big.iso') && s.includes('limit')),
    JSON.stringify(ctx.said));
  const b = standIn();
  ctx.session = b;
  ctx.offerFiles([{ name: 'small.txt', size: 100 }, { name: 'notes.txt', size: 200 }]);
  const offer = b.sent.find(e => e.ident === 'initiate_file_copy');
  check('an upload under the limit sends every file', !!offer && offer.value.length === 2,
    JSON.stringify(b.sent.map(e => e.value)));
}

{
  const ctx = sandbox({ max_file_bytes: 10 * MB });
  const a = standIn();
  ctx.session = a;
  ctx.remoteFiles = [{ name: 'dump.bak', size: 20 * MB }];
  // A download that went ahead would wait on the remote for ever, so the check waits 50 ms at most.
  await Promise.race([ctx.downloadRemoteFile(0, { append() {} }), new Promise(r => setTimeout(r, 50))]);
  check('a download over the limit asks the remote for nothing',
    a.sent.every(e => e.ident !== 'request_file_contents'), JSON.stringify(a.sent.map(e => e.ident)));
  check('a download over the limit says so', ctx.said.some(s => s.includes('limit')), JSON.stringify(ctx.said));
}

{
  const ctx = sandbox(null);
  check("the server sign-in starts with the server's default domain",
    ctx.startDomain({}, { domain: 'PLANT' }) === 'PLANT');
  check('a domain just tried wins over the default', ctx.startDomain({ domain: 'OT' }, { domain: 'PLANT' }) === 'OT');
  check('no default leaves the domain empty', ctx.startDomain({}, {}) === '');
}

console.log(`passed=${passed} failed=${failed}`);
process.exit(failed ? 1 : 0);
