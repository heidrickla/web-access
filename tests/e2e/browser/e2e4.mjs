// File scanning through a real Windows RDP server (NLA): files dropped on the page reach the
// remote only once scanned clean, files copied on the remote reach the page only once scanned
// clean, and the EICAR test file is refused both ways. Steps on the remote run in its RDP session
// through scan.sh's agent: this script writes /work/remote/req-<n> and waits for done-<n>.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { env, check, summary, launch, newPage, shot, signIn, waitConnected, disconnect } from './lib.mjs';

const P4 = 'http://127.0.0.1:8446';
const SERVER = 'win-01';

let seq = 0;
async function remote(step, ms = 180000) {
  const id = String(++seq);
  fs.writeFileSync(`/work/remote/req-${id}`, step);
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const done = `/work/remote/done-${id}`;
    if (fs.existsSync(done)) return fs.readFileSync(done, 'utf8').trim();
    await new Promise(r => setTimeout(r, 300));
  }
  throw new Error(`remote step ${step} did not finish`);
}

// The EICAR test file, kept reversed so this source never carries it.
const eicar = () => Buffer.from([...'*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X'].reverse().join(''), 'latin1');
const sha = b => crypto.createHash('sha256').update(b).digest('hex').toUpperCase();

/// Waits for the page to say something matching `re`; the status line keeps the last message.
async function said(page, re, ms = 60000) {
  try {
    await page.waitForFunction(r => new RegExp(r).test(document.getElementById('status').textContent),
      re.source, { timeout: ms });
    return true;
  } catch {
    return false;
  }
}

const browser = await launch();
const { page } = await newPage(browser);
try {
  await signIn(page, P4, 'devscan', env.LOCAL_PASS);
  const me = await page.evaluate(() => fetch('/api/me').then(r => r.json()));
  check('the page is told files are scanned', me.scanning === true, JSON.stringify(me));

  await page.click(`button.srv:has-text("${SERVER}")`);
  await page.waitForSelector('#signin[open]');
  await page.fill('#u', env.WIN_USER);
  await page.fill('#p', env.WIN_PASS);
  await page.click('#signin-go');
  await waitConnected(page, 90000);
  check('an NLA session opens through the scanning relay', true);
  const ready = await remote('wait-session');
  check('the desktop is signed in on the remote', ready === 'ready', ready);
  await shot(page, 'e2e4-desktop');

  // Upload, clean: the remote pastes it only after the scan.
  const body = Buffer.from('notes from the browser, a harmless file\n');
  await remote('clear-in');
  await page.setInputFiles('#picker', { name: 'notes.txt', mimeType: 'text/plain', buffer: body });
  check('a clean upload passes the scan', await said(page, /notes\.txt passed the scan; paste on win-01/));
  await remote('paste');
  const pasted = await remote('list-in');
  check('the pasted file on the remote is the one dropped, byte for byte',
    pasted === `notes.txt ${body.length} ${sha(body)}`, pasted);

  // Upload, the EICAR test file: refused, and the remote clipboard holds nothing to paste.
  await remote('clear-in');
  await page.setInputFiles('#picker', { name: 'test.com', mimeType: 'application/octet-stream', buffer: eicar() });
  check('the EICAR test file is not sent', await said(page, /test\.com not sent to win-01: test\.com: malware detected/));
  check('and is shown as bad', await page.evaluate(() => document.getElementById('status').classList.contains('bad')));
  await remote('paste-nothing');
  const none = await remote('list-in');
  check('nothing reaches the remote', none === '', none);

  // Download, clean: offered to the page after the scan, and the bytes are the remote's.
  await remote('set-report');
  check('a clean download passes the scan', await said(page, /report\.txt from win-01 passed the scan/));
  await page.waitForSelector('#incoming li:has-text("report.txt") button', { state: 'attached', timeout: 30000 });
  await page.click('#rail-toggle');
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 60000 }),
    page.click('#incoming li:has-text("report.txt") button'),
  ]);
  const got = fs.readFileSync(await download.path());
  check('the downloaded file is the remote one', got.toString() === 'quarterly report, a harmless file', got.toString());

  // Download, the EICAR test file: refused, never offered to the page.
  await remote('set-eicar');
  check('the EICAR test file on the remote is refused', await said(page, /eicar\.com from win-01 refused: eicar\.com: malware detected/));
  const listed = await page.$$eval('#incoming li .fname', els => els.map(e => e.textContent));
  check('and never offered to the page', !listed.includes('eicar.com'), JSON.stringify(listed));

  const activity = await page.evaluate(() => fetch('/api/admin/audit?q=file.&limit=20').then(r => r.json()));
  const lines = activity.entries.map(e => `${e.action} ${e.detail}`);
  for (const want of [
    /^file\.upload notes\.txt \(\d+ bytes\), win-01: passed$/,
    /^file\.upload test\.com \(68 bytes\), win-01: refused: test\.com: malware detected$/,
    /^file\.download report\.txt \(\d+ bytes\), win-01: passed$/,
    /^file\.download eicar\.com \(68 bytes\), win-01: refused: eicar\.com: malware detected$/,
  ]) check('the Activity tab records ' + want.source, lines.some(l => want.test(l)), JSON.stringify(lines));

  const m = await page.evaluate(() => fetch('/api/admin/migration').then(r => r.json()));
  check('the Migration tab shows the scanner admitting files', m.scan && m.scan.admitting === true
    && /^command sh/.test(m.scan.health.scanner), JSON.stringify(m.scan));

  await shot(page, 'e2e4-done');
  await page.click('#panel-close');
  await disconnect(page);
} catch (err) {
  check('file scanning run', false, String(err && err.stack || err));
  await shot(page, 'e2e4-error').catch(() => {});
} finally {
  await browser.close();
}
process.exit(summary() ? 1 : 0);
