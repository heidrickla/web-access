// Shared helpers for the web-access browser tests. Fixture passwords are read from fixtures.env and
// never logged.
import fs from 'node:fs';
import { chromium } from 'playwright';

export const env = Object.fromEntries(
  fs.readFileSync('/work/fixtures.env', 'utf8').trim().split('\n').map(l => {
    const i = l.indexOf('=');
    return [l.slice(0, i), l.slice(i + 1)];
  }),
);

export const P1 = 'http://127.0.0.1:8443';
export const P2 = 'http://127.0.0.1:8444';

let passed = 0, failed = 0;
export function check(name, ok, detail = '') {
  if (ok) { passed++; console.log('PASS ' + name); }
  else { failed++; console.log('FAIL ' + name + (detail ? ': ' + detail : '')); }
}
export function summary() {
  console.log(`passed=${passed} failed=${failed}`);
  return failed;
}

export async function launch() {
  return chromium.launch();
}

export async function newPage(browser, opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, acceptDownloads: true, ...opts });
  const page = await ctx.newPage();
  page.on('console', m => { if (m.type() === 'error') console.log('  console error: ' + m.text()); });
  page.on('pageerror', e => console.log('  page error: ' + e.message));
  return { ctx, page };
}

export async function shot(page, name) {
  await page.screenshot({ path: `/work/shots/${name}.png` });
}

export async function signIn(page, base, username, password) {
  await page.goto(base + '/');
  await page.waitForSelector('#login:not([hidden]), #list:not([hidden])');
  if (await page.isVisible('#list')) return;
  await page.fill('#lu', username);
  await page.fill('#lp', password);
  await page.click('#login-go');
  await page.waitForSelector('#list:not([hidden]), #login-error:not([hidden])');
}

export const connected = page => page.evaluate(() => document.body.classList.contains('connected'));

export async function waitConnected(page, ms = 60000) {
  await page.waitForFunction(() => document.body.classList.contains('connected'), null, { timeout: ms });
}

export async function waitDisconnected(page, ms = 60000) {
  await page.waitForFunction(() => !document.body.classList.contains('connected'), null, { timeout: ms });
}

export async function disconnect(page) {
  await page.click('#rail-toggle');
  await page.click('#panel-disconnect');
  await waitDisconnected(page);
}

export const status = page => page.textContent('#status');

/// xrdp is not an NLA server and the browser client never sets autologon, so xrdp shows its own
/// login box with the username filled. Type the fixture password into it through the canvas, which
/// also exercises keyboard input.
export async function xrdpLogin(page) {
  await page.waitForTimeout(3000);
  await page.click('#screen', { position: { x: 680, y: 467 } });
  await page.keyboard.type(env.OPS_PASS, { delay: 20 });
  await page.keyboard.press('Enter');
  await page.waitForTimeout(9000);
}
