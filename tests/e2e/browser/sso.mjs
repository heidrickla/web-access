// Single sign-on through Keycloak against proxy 5: the round trip, a replayed response, a second
// sign-in while the identity provider's session holds, and an account the directory does not have.
import { env, check, summary, launch, newPage, shot } from './lib.mjs';

const P5 = 'https://localhost:8447';
const IDP = 'http://127.0.0.1:8180/realms/corp/';

const browser = await launch();
try {
  const { ctx, page } = await newPage(browser, { ignoreHTTPSErrors: true });
  let posted = null;
  page.on('request', r => {
    if (r.method() === 'POST' && r.url() === P5 + '/api/saml/acs') posted = r.postData();
  });

  await page.goto(P5 + '/');
  await page.waitForSelector('#login:not([hidden])');
  await page.waitForSelector('#sso-offer:not([hidden])');
  check('the sign-in page offers single sign-on', await page.isVisible('#sso'));
  await shot(page, 'sso-01-offer');

  await page.click('#sso');
  await page.waitForSelector('#username', { timeout: 30000 });
  check('the identity provider asks who is signing in', page.url().startsWith(IDP), page.url());
  await page.fill('#username', 'jdoe');
  await page.fill('#password', env.USER_PASS);
  await page.click('#kc-login');
  await page.waitForSelector('#list:not([hidden])', { timeout: 30000 });
  check('jdoe comes back to the server list', page.url() === P5 + '/', page.url());
  const me = await page.evaluate(() => fetch('/api/me').then(r => r.json()));
  check('the session is jdoe\'s', me.username === 'jdoe', JSON.stringify(me));
  const cookies = await ctx.cookies(P5);
  check('the flow cookie is spent', !cookies.some(c => c.name === 'wa_saml'));
  check('the session cookie is SameSite=Strict', cookies.some(c => c.name === 'wa_session' && c.sameSite === 'Strict'));
  check('the renewal dialog offers single sign-on', !(await page.$eval('#renew-sso-offer', e => e.hidden)));
  await shot(page, 'sso-02-list');

  // The same response again, from the same browser: its flow cookie is gone and its IDs spent.
  check('the identity provider posted a SAMLResponse', Boolean(posted && posted.includes('SAMLResponse=')));
  const replay = await ctx.request.post(P5 + '/api/saml/acs', {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: posted || '',
    failOnStatusCode: false,
  });
  check('a replayed response is refused', replay.status() === 401, String(replay.status()));

  // Signed out, then single sign-on again: the identity provider's session holds, so no form.
  await page.click('#signout');
  await page.waitForSelector('#login:not([hidden])');
  await page.waitForSelector('#sso-offer:not([hidden])');
  let formShown = false;
  page.on('framenavigated', f => { if (f === page.mainFrame() && f.url().startsWith(IDP + 'login-actions')) formShown = true; });
  await page.click('#sso');
  await page.waitForSelector('#list:not([hidden])', { timeout: 30000 });
  check('a second single sign-on returns without a password', !formShown && page.url() === P5 + '/', page.url());
  await ctx.close();

  // An identity provider account whose SID no directory account has.
  const ghost = await newPage(browser, { ignoreHTTPSErrors: true });
  await ghost.page.goto(P5 + '/api/saml/start');
  await ghost.page.waitForSelector('#username', { timeout: 30000 });
  await ghost.page.fill('#username', 'ghost');
  await ghost.page.fill('#password', env.USER_PASS);
  await ghost.page.click('#kc-login');
  await ghost.page.waitForSelector('p.error', { timeout: 30000 });
  const said = await ghost.page.textContent('p.error');
  check('an account the directory does not have is refused, saying why', said.includes('no account in the directory has the SID'), said);
  const ghostMe = await ghost.page.evaluate(() => fetch('/api/me').then(r => r.status));
  check('and is not signed in', ghostMe === 401, String(ghostMe));
  await shot(ghost.page, 'sso-03-refused');
  await ghost.ctx.close();
} finally {
  await browser.close();
}
process.exit(summary() ? 1 : 0);
