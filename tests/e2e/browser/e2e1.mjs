// Phase 1: sign-in, the grouped list, connect with save, reconnect with the saved credential,
// closing the browser and coming back, and the admin pages.
import fs from 'node:fs';
import { env, P1, check, summary, launch, newPage, shot, signIn, connected, waitConnected, disconnect, status, xrdpLogin } from './lib.mjs';

const browser = await launch();
try {
  const { ctx, page } = await newPage(browser);

  // Sign-in page and a refusal.
  await page.goto(P1 + '/');
  await page.waitForSelector('#login:not([hidden])');
  await shot(page, '01-signin');
  await page.fill('#lu', 'jdoe');
  await page.fill('#lp', 'not-the-password');
  await page.click('#login-go');
  await page.waitForSelector('#login-error:not([hidden])');
  check('a wrong password shows an error on the sign-in page', (await page.textContent('#login-error')).includes('not correct'));

  // Signed in: the list, grouped, collapsible.
  await signIn(page, P1, 'jdoe', env.USER_PASS);
  check('jdoe lands on the server list', await page.isVisible('#list'));
  const groups = await page.$$eval('details.group .gname', els => els.map(e => e.textContent));
  check('groups render in order', JSON.stringify(groups) === JSON.stringify(['Test Targets', 'Historians']), JSON.stringify(groups));
  check('rows carry name and host', (await page.textContent('li.row .host')) === '127.0.0.1');
  await shot(page, '02-list');

  await page.fill('#filter', 'hist');
  const visible = await page.$$eval('li.row', lis => lis.filter(li => !li.hidden).map(li => li.querySelector('.srv').textContent));
  check('the filter narrows the rows', JSON.stringify(visible) === '["hist-01"]', JSON.stringify(visible));
  await page.fill('#filter', '');
  await page.click('details.group:has-text("Historians") > summary');
  await page.reload();
  await page.waitForSelector('#list:not([hidden])');
  const histOpen = await page.$eval('details.group[data-key="Historians"]', d => d.open);
  check('a collapsed group stays collapsed across a reload', histOpen === false);
  await page.click('#expand-all');

  // Connect, typing credentials and asking to save them.
  await page.click('button.srv:has-text("xrdp-01")');
  await page.waitForSelector('dialog#signin[open]');
  await page.fill('#u', 'ops');
  await page.fill('#p', env.OPS_PASS);
  await page.check('#save');
  await shot(page, '03-server-signin');
  await page.click('#signin-go');
  await waitConnected(page);
  await xrdpLogin(page);
  await shot(page, '04-desktop');
  check('the desktop is shown full window', await connected(page));
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('saved'), null, { timeout: 10000 }).catch(() => {});
  check('the credential was saved after the server accepted it', (await status(page)).includes('credentials saved'), await status(page));

  // Disconnect: the list shows Reconnect and the saved marker.
  await disconnect(page);
  await page.waitForSelector('li.row .mark.reconnect', { timeout: 10000 }).catch(() => {});
  check('the list marks the server Reconnect after a disconnect', await page.isVisible('li.row .mark.reconnect'));
  check('the list marks the saved credential', await page.isVisible('li.row .mark.saved'));
  await shot(page, '05-list-reconnect');

  // One click with a saved credential: no dialog.
  await page.click('button.srv:has-text("xrdp-01")');
  await waitConnected(page);
  check('a saved credential connects without the dialog', !(await page.isVisible('dialog#signin[open]')));
  await xrdpLogin(page);
  await shot(page, '05b-reconnected');

  // Close the browser mid-session and come back.
  const state = await ctx.storageState();
  fs.writeFileSync('/work/jdoe-state.json', JSON.stringify(state));
  const persistent = state.cookies.find(c => c.name === 'wa_session');
  check('the session cookie outlives the browser (24h expiry)', persistent && persistent.expires > Date.now() / 1000 + 23 * 3600,
    persistent ? String(persistent.expires) : 'no cookie');
  await ctx.close();
  await new Promise(r => setTimeout(r, 3000));

  const again = await newPage(browser, { storageState: '/work/jdoe-state.json' });
  await again.page.goto(P1 + '/');
  await again.page.waitForSelector('#list:not([hidden]), #login:not([hidden])');
  check('reopening the browser lands on the list with no sign-in', await again.page.isVisible('#list'));
  await again.page.waitForSelector('li.row .mark.reconnect', { timeout: 10000 }).catch(() => {});
  check('the server is marked Reconnect after the browser closed', await again.page.isVisible('li.row .mark.reconnect'));
  await again.page.click('button.srv:has-text("xrdp-01")');
  await waitConnected(again.page);
  await xrdpLogin(again.page);
  await shot(again.page, '06-reattached');
  check('reconnecting after a browser restart opens the desktop', await connected(again.page));
  await disconnect(again.page);

  // Forget the saved credential.
  await again.page.click('li.row:has-text("xrdp-01") button.forget');
  await again.page.waitForFunction(() => !document.querySelector('li.row .mark.saved'), null, { timeout: 10000 }).catch(() => {});
  check('forgetting removes the saved marker', !(await again.page.isVisible('li.row .mark.saved')));
  await again.ctx.close();

  // Admin pages as the bootstrap admin.
  const admin = await newPage(browser);
  await signIn(admin.page, P1, 'boss', env.USER_PASS);
  check('the admin link shows for an administrator', await admin.page.isVisible('#admin-link'));
  await admin.page.goto(P1 + '/admin');
  await admin.page.waitForSelector('#tabs:not([hidden])');
  await admin.page.waitForSelector('#user-table tbody tr');
  await admin.page.click('#user-table tbody tr:has-text("jdoe")');
  await admin.page.waitForSelector('#user-detail:not([hidden])');
  await shot(admin.page, '07-admin-users');
  for (const tab of ['servers', 'groups', 'activity', 'migration']) {
    await admin.page.click(`nav.tabs button[data-tab="${tab}"]`);
    await admin.page.waitForTimeout(700);
    await shot(admin.page, '08-admin-' + tab);
  }
  const actions = await admin.page.$$eval('#audit-table tbody td:nth-child(3)', tds => tds.map(t => t.textContent));
  check('activity records the session and the saved credential',
    actions.includes('session.open') && actions.includes('credential.save'), JSON.stringify(actions.slice(0, 12)));
  await admin.ctx.close();

  // A non-admin gets the denial page, not the tabs.
  const plain = await newPage(browser, { storageState: '/work/jdoe-state.json' });
  await plain.page.goto(P1 + '/admin');
  await plain.page.waitForSelector('#denied:not([hidden])');
  check('a non-admin sees the denial page', !(await plain.page.isVisible('#tabs')));
  await plain.ctx.close();
} catch (err) {
  check('phase 1 ran to the end', false, err.message);
} finally {
  await browser.close();
  process.exitCode = summary() ? 1 : 0;
}
