// Phase 2: revoking the account in the directory ends a live session and the sign-in.
// The wrapper disables jdoe in Samba once /work/revoke-ready appears.
import fs from 'node:fs';
import { env, P1, check, summary, launch, newPage, signIn, connected, waitConnected, waitDisconnected, xrdpLogin, shot } from './lib.mjs';

const browser = await launch();
try {
  const { page } = await newPage(browser);
  await signIn(page, P1, 'jdoe', env.USER_PASS);
  check('jdoe is signed in', await page.isVisible('#list'));
  await page.click('button.srv:has-text("xrdp-01")');
  await page.waitForSelector('dialog#signin[open]');
  await page.fill('#u', 'ops');
  await page.fill('#p', env.OPS_PASS);
  await page.click('#signin-go');
  await waitConnected(page);
  await xrdpLogin(page);
  check('jdoe has a live session', await connected(page));

  fs.writeFileSync('/work/revoke-ready', String(Date.now()));
  const started = Date.now();
  await waitDisconnected(page, 120000);
  const took = Math.round((Date.now() - started) / 1000);
  check('disabling the account ended the live session', !(await connected(page)), `after ${took}s`);
  console.log(`  session ended ${took}s after the account was disabled`);

  await page.reload();
  await page.waitForSelector('#login:not([hidden]), #list:not([hidden])');
  check('the sign-in session was revoked too', await page.isVisible('#login'));
  await signIn(page, P1, 'jdoe', env.USER_PASS);
  check('a disabled account cannot sign in again', await page.isVisible('#login-error'));
  await shot(page, '09-revoked');
} catch (err) {
  check('phase 2 ran to the end', false, err.message);
} finally {
  await browser.close();
  process.exitCode = summary() ? 1 : 0;
}
