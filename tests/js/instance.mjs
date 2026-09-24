// Runs each page's api() from web/app.js and web/admin.js against a stand-in fetch: requests carry
// the data instance the page loaded from, and a page that sees another one reloads instead of going
// on with ids from the replaced database.
//   node tests/js/instance.mjs            (APP_JS=<path> / ADMIN_JS=<path> check other copies)
import fs from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const here = p => fileURLToPath(new URL(p, import.meta.url));
const pages = [
  ['app.js', process.env.APP_JS || here('../../web/app.js')],
  ['admin.js', process.env.ADMIN_JS || here('../../web/admin.js')],
];

/// A top-level function declaration's text, found by name, braces matched from the `) {` that ends
/// its parameters (a destructured parameter has braces of its own).
function extract(source, name) {
  const start = source.search(new RegExp(`^(async )?function ${name}\\(`, 'm'));
  if (start < 0) throw new Error(`no function ${name}`);
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

/// A page's api() with a stand-in fetch whose answers carry `reply.instance`.
function page(file) {
  const sent = [];
  const state = { reloads: 0, reply: { instance: 'one', status: 200 } };
  const ctx = {
    dataInstance: null,
    SignedOut: class extends Error {},
    location: { reload() { state.reloads++; }, href: '' },
    fetch: async (_path, init) => {
      sent.push(init.headers['X-Data-Instance'] ?? null);
      const { instance, status } = state.reply;
      return {
        status,
        ok: status < 400,
        headers: { get: h => (h.toLowerCase() === 'x-data-instance' ? instance : null) },
        text: async () => '{}',
      };
    },
    JSON, Error,
  };
  vm.createContext(ctx);
  vm.runInContext(extract(fs.readFileSync(file, 'utf8'), 'api'), ctx);
  return { ctx, sent, state };
}

for (const [name, file] of pages) {
  const p = page(file);
  await p.ctx.api('GET', '/api/me');
  check(`${name}: the first answer's instance is kept`, p.ctx.dataInstance === 'one', String(p.ctx.dataInstance));
  await p.ctx.api('POST', '/api/connect', {});
  check(`${name}: a request carries the instance`, p.sent[1] === 'one', String(p.sent[1]));
  p.state.reply = { instance: 'two', status: 200 };
  const stopped = await p.ctx.api('GET', '/api/me/servers').then(() => false, () => true);
  check(`${name}: another instance reloads the page instead of going on`,
    stopped && p.state.reloads === 1 && p.ctx.dataInstance === 'one',
    `stopped=${stopped} reloads=${p.state.reloads} instance=${p.ctx.dataInstance}`);
}

console.log(`passed=${passed} failed=${failed}`);
process.exitCode = failed ? 1 : 0;
