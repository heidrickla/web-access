// Runs functions from web/app.js outside a browser, against stand-in sessions, to check that work
// started for one RDP session never reaches the next.
//   node tests/js/sessions.mjs            (APP_JS=<path> checks another copy of app.js)
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const path = process.env.APP_JS || fileURLToPath(new URL('../../web/app.js', import.meta.url));
const source = fs.readFileSync(path, 'utf8');

/// A top-level function declaration's text, found by name, braces matched from the `) {` that ends
/// its parameters (a destructured parameter has braces of its own).
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

function sandbox() {
  const ctx = {
    session: null, outgoing: [], pending: new Map(), nextStream: 1,
    FLAG_SIZE: 0x1, FLAG_RANGE: 0x2,
    Extension: class { constructor(ident, value) { this.ident = ident; this.value = value; } },
    said: [],
    describe: e => String((e && e.message) || e),
    setTimeout: () => 0,   // askRemote's 30 s answer timeout plays no part here
    Uint8Array, DataView, BigInt, Number, Error, Promise, Map,
  };
  ctx.say = text => ctx.said.push(text);
  vm.createContext(ctx);
  vm.runInContext(['extOn', 'ext', 'answerFileRequest', 'askRemote'].map(extract).join('\n'), ctx);
  return ctx;
}

function standIn() {
  const sent = [];
  return { sent, invokeExtension(e) { sent.push(e); } };
}

/// A file whose read finishes only when `finish` is called.
function slowFile() {
  const f = { size: 4, finish: null };
  f.slice = () => ({ arrayBuffer: () => new Promise(r => { f.finish = () => r(new Uint8Array([1, 2, 3, 4]).buffer); }) });
  return f;
}

const REQ = { index: 0, flags: 0x2, position: 0, size: 4, streamId: 7 };

{
  const ctx = sandbox();
  const a = standIn();
  const file = slowFile();
  ctx.outgoing = [file];
  ctx.session = a;
  const answered = ctx.answerFileRequest(a, REQ);
  file.finish();
  await answered;
  check('an upload read answers the session that asked', a.sent.length === 1 && a.sent[0].value.is_error === false,
    JSON.stringify(a.sent.map(e => e.value.is_error)));
}

{
  const ctx = sandbox();
  const a = standIn();
  const b = standIn();
  const file = slowFile();
  ctx.outgoing = [file];
  ctx.session = a;
  const answered = ctx.answerFileRequest(a, REQ);
  ctx.session = b;   // A ended and B opened while the file was being read
  file.finish();
  await answered;
  check('an upload read that finishes after its session ended sends nothing to the next one',
    b.sent.length === 0 && a.sent.length === 0, `A=${a.sent.length} B=${b.sent.length}`);
  check('and reports nothing about the ended session', ctx.said.length === 0, JSON.stringify(ctx.said));
}

{
  const ctx = sandbox();
  const a = standIn();
  ctx.session = a;
  ctx.askRemote(a, 0, 0x2, 0, 4);
  check('a download request goes to the session it was started for', a.sent.length === 1);
}

{
  const ctx = sandbox();
  const a = standIn();
  const b = standIn();
  ctx.session = b;
  ctx.askRemote(a, 0, 0x2, 0, 4).catch(() => {});
  check('a download continuing after its session ended asks nothing of the next one',
    b.sent.length === 0 && ctx.pending.size === 0, `B=${b.sent.length} pending=${ctx.pending.size}`);
}

console.log(`passed=${passed} failed=${failed}`);
process.exitCode = failed ? 1 : 0;
