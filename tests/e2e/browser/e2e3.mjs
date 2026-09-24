// Phase 3: the cutover drill through the admin GUI. Proxy 1 is the old host, proxy 2 the new one,
// each with its own data directory and key. The wrapper starts proxy 2 empty.
import fs from 'node:fs';
import { env, P1, P2, check, summary, launch, newPage, signIn, connected, waitConnected, disconnect, xrdpLogin, shot, status } from './lib.mjs';

const browser = await launch();
try {
  // jdoe saves a credential on the old host and keeps their sign-in.
  const jdoe = await newPage(browser);
  await signIn(jdoe.page, P1, 'jdoe', env.USER_PASS);
  await jdoe.page.click('button.srv:has-text("xrdp-01")');
  await jdoe.page.waitForSelector('dialog#signin[open]');
  await jdoe.page.fill('#u', 'ops');
  await jdoe.page.fill('#p', env.OPS_PASS);
  await jdoe.page.check('#save');
  await jdoe.page.click('#signin-go');
  await waitConnected(jdoe.page);
  await jdoe.page.waitForFunction(() => document.getElementById('status').textContent.includes('saved'), null, { timeout: 10000 });
  check('jdoe saved a credential on the old host', (await status(jdoe.page)).includes('credentials saved'));
  await disconnect(jdoe.page);
  fs.writeFileSync('/work/jdoe-old.json', JSON.stringify(await jdoe.ctx.storageState()));
  await jdoe.ctx.close();

  // Export and freeze on the old host.
  const old = await newPage(browser);
  await signIn(old.page, P1, 'boss', env.USER_PASS);
  await old.page.goto(P1 + '/admin#migration');
  await old.page.waitForSelector('#export-form');
  await old.page.fill('#exp-pass', 'not-the-recovery-passphrase');
  await old.page.click('#exp-go');
  await old.page.waitForFunction(() => document.getElementById('status').classList.contains('bad'), null, { timeout: 15000 });
  check('export refuses a wrong passphrase', (await status(old.page)).includes('not correct'), await status(old.page));
  await old.page.fill('#exp-pass', env.RECOVERY_PASS);
  await old.page.check('#exp-freeze');
  const [download] = await Promise.all([old.page.waitForEvent('download'), old.page.click('#exp-go')]);
  const name = download.suggestedFilename();
  await download.saveAs('/work/export.zip');
  check('the export downloads as a zip named for the host', /^web-access-export-.+-\d{8}T\d{6}Z\.zip$/.test(name), name);
  await old.page.waitForSelector('#unfreeze:not([hidden])');
  check('the old host shows frozen', await old.page.isVisible('#banner'));
  await shot(old.page, '10-old-frozen');

  // Frozen: admin edits and credential saves are refused, sign-in still works.
  await old.page.click('nav.tabs button[data-tab="groups"]');
  await old.page.fill('#new-group', 'After export');
  await old.page.click('#add-group button[type="submit"]');
  await old.page.waitForFunction(() => document.getElementById('status').classList.contains('bad'), null, { timeout: 10000 });
  check('a frozen host refuses admin edits', (await status(old.page)).includes('frozen'), await status(old.page));
  const frozenSave = await newPage(browser, { storageState: '/work/jdoe-old.json' });
  await frozenSave.page.goto(P1 + '/');
  const saveStatus = await frozenSave.page.evaluate(async () => {
    const list = await (await fetch('/api/me/servers')).json();
    const id = list.groups[0].servers[0].id;
    const r = await fetch('/api/credentials/' + id, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'x', password: 'y' }),
    });
    return r.status;
  });
  check('a frozen host refuses credential saves', saveStatus === 409, String(saveStatus));
  await frozenSave.ctx.close();

  // Import on the new host.
  const neu = await newPage(browser);
  await signIn(neu.page, P2, 'boss', env.USER_PASS);
  await neu.page.goto(P2 + '/admin#migration');
  await neu.page.waitForSelector('#import-upload');
  await neu.page.setInputFiles('#imp-file', '/work/export.zip');
  await neu.page.click('#imp-upload-go');
  await neu.page.waitForSelector('#import-confirm:not([hidden])');
  const facts = await neu.page.textContent('#imp-facts');
  check('the upload shows what the export holds', facts.includes('Saved credentials') && facts.includes('Users'), facts);
  check('a fresh host does not ask for its name', !(await neu.page.isVisible('#imp-host-label')));
  await shot(neu.page, '11-import-confirm');
  await neu.page.fill('#imp-pass', 'not-the-recovery-passphrase');
  await neu.page.click('#imp-go');
  await neu.page.waitForFunction(() => document.getElementById('status').classList.contains('bad'), null, { timeout: 15000 });
  check('import refuses a wrong passphrase and keeps the upload', await neu.page.isVisible('#import-confirm'));
  await neu.page.fill('#imp-pass', env.RECOVERY_PASS);
  await neu.page.click('#imp-go');
  await neu.page.waitForFunction(() => document.getElementById('status').textContent.startsWith('imported')
    || location.pathname === '/', null, { timeout: 30000 });
  check('the import completes', true);
  await neu.ctx.close();

  // jdoe, with the cookie from the OLD host, on the NEW host: still signed in, credential intact.
  const moved = await newPage(browser, { storageState: '/work/jdoe-old.json' });
  await moved.page.goto(P2 + '/');
  await moved.page.waitForSelector('#list:not([hidden]), #login:not([hidden])');
  check('the user is still signed in after the cutover', await moved.page.isVisible('#list'));
  check('the saved credential moved', await moved.page.isVisible('li.row .mark.saved'));
  await moved.page.click('button.srv:has-text("xrdp-01")');
  await waitConnected(moved.page);
  check('the moved credential connects with no prompt', !(await moved.page.isVisible('dialog#signin[open]')));
  await xrdpLogin(moved.page);
  await shot(moved.page, '12-after-cutover');
  check('the session runs through the new host', await connected(moved.page));
  await disconnect(moved.page);
  await moved.ctx.close();

  // The new host is not frozen; the old one is unfrozen to leave the fixtures tidy.
  const after = await newPage(browser);
  await signIn(after.page, P2, 'boss', env.USER_PASS);
  const newFrozen = await after.page.evaluate(async () => (await (await fetch('/api/admin/migration')).json()).frozen);
  check('the imported database is not frozen', newFrozen === false);
  await signIn(after.page, P1, 'boss', env.USER_PASS);
  await after.page.evaluate(() => fetch('/api/admin/migration/unfreeze', { method: 'POST' }));
  await after.ctx.close();
} catch (err) {
  check('phase 3 ran to the end', false, err.message);
} finally {
  await browser.close();
  process.exitCode = summary() ? 1 : 0;
}
