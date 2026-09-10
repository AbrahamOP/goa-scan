// Onglet API : appels fetch capturés (méthode, :id, statut, auth), secrets dans l'URL, doc OpenAPI
// trouvée en mode actif. Lancer d'abord : python3 tests/e2e/fixture-active.py &
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
const EXT = new URL('../../', import.meta.url).pathname;
const OUT = process.env.OUT || '/tmp/goa-scan-shots/';
fs.mkdirSync(OUT, { recursive: true });
const URL_ = 'http://127.0.0.1:8766/';

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [EXT], args: ['--no-sandbox'] });
const errors = [];
let failed = 0;
const check = (label, ok, got) => { if (!ok) failed++; console.log(ok ? 'ok ' : 'KO ', label, ok ? '' : JSON.stringify(got)); };
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  const base = `chrome-extension://${new URL(sw.url()).host}/popup.html`;
  // Juste après le lancement, le service worker n'a pas encore branché webRequest : on l'attend.
  await (await sw.worker()).evaluate(() => ready);
  const page = await browser.newPage();
  await page.goto(URL_, { waitUntil: 'networkidle0' });

  const r = await browser.newPage();
  r.on('pageerror', (e) => errors.push(e.message));
  // Les 404 des sondes (fichiers absents) sont attendues.
  r.on('console', (m) => { if (m.type() === 'error' && !/status of 404/.test(m.text())) errors.push(m.text()); });
  await r.goto(base);
  const tabId = await r.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url === u)?.id, URL_);
  await r.setViewport({ width: 460, height: 620 });
  await r.goto(`${base}?tab=${tabId}`);
  await r.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });

  const apis = await r.evaluate(() => state.report.apis.map((a) => ({ m: a.method, url: a.url, st: a.statuses, auth: a.auth, params: a.params, secrets: a.secrets, ct: a.ctype })));
  console.log(JSON.stringify(apis, null, 1));
  const by = (m, path) => apis.find((a) => a.m === m && a.url.endsWith(path));
  check('GET /api/users/:id regroupé (2 appels)', by('GET', '/api/users/:id') && apis.filter((a) => a.url.endsWith('/api/users/:id')).length === 1, apis);
  check('Bearer détecté', by('GET', '/api/users/:id')?.auth === 'Bearer', by('GET', '/api/users/:id'));
  check('POST /api/orders 201 Basic json', by('POST', '/api/orders')?.st.includes(201) && by('POST', '/api/orders')?.auth === 'Basic' && by('POST', '/api/orders')?.ct === 'application/json', by('POST', '/api/orders'));
  check('/api/fail 500', by('GET', '/api/fail')?.st.includes(500), by('GET', '/api/fail'));
  check('aucune valeur de jeton stockée', !JSON.stringify(apis).includes('eyJ'), apis);
  const ids = await r.evaluate(() => state.report.findings.filter((f) => f.cat === 'api' && !f.ok).map((f) => `${f.sev}:${f.id}`));
  check('constats API', ['medium:api-url-secrets', 'low:api-basic', 'info:api-5xx'].every((x) => ids.includes(x)), ids);

  // Secrets dans le JS : inline (AWS, clé Google publique, affectation) + app.js (Stripe, service_role).
  const js = await r.evaluate(() => ({
    scanned: state.raw.jsSecrets?.scanned,
    hits: (state.raw.jsSecrets?.hits || []).map((h) => `${h.id}:${h.public ? 'pub' : h.sev}@${h.source}`),
    findings: state.report.findings.filter((f) => f.id.startsWith('js-') && !f.ok).map((f) => `${f.sev}:${f.id}`),
    raw: JSON.stringify(state.raw),
  }));
  console.log(JSON.stringify({ scanned: js.scanned, hits: js.hits, findings: js.findings }, null, 1));
  const wanted = ['critical:js-stripe-secret', 'critical:js-supabase-service-role', 'high:js-aws-access-key', 'info:js-public-keys', 'info:js-to-check'];
  check('secrets JS : constats attendus', wanted.every((x) => js.findings.includes(x)), js.findings);
  check('secrets JS : app.js lu', js.hits.some((h) => h.includes('@127.0.0.1:8766/static/app.js')), js.hits);
  const SK = 'sk_' + 'live_' + 'Z9y8X7w6'.repeat(3);
  const AWS = 'AK' + 'IA' + 'Q3EGRTZ7LWBN4XKD';
  check('secrets JS : aucune valeur complète conservée', !js.raw.includes(SK) && !js.raw.includes(AWS), 'valeur en clair dans state.raw');

  // Endpoints cités dans le JS : recoupés avec les appels, statiques et espaces de noms écartés.
  const eps = await r.evaluate(() => state.report.jsEndpoints.map((e) => ({ url: e.url, called: e.called, sensitive: e.sensitive, third: e.third })));
  console.log(JSON.stringify(eps, null, 1));
  const ep = (end) => eps.find((e) => e.url.endsWith(end));
  check('endpoint JS appelé : /api/users/:id', ep('/api/users/:id')?.called === true, eps);
  check('endpoint JS sensible non appelé : /api/internal/export/:param', ep('/api/internal/export/:param')?.sensitive && !ep('/api/internal/export/:param').called, eps);
  check('endpoint JS autre domaine : api.exemple.fr/v1/orders', ep('api.exemple.fr/v1/orders')?.third === true, eps);
  check('ni logo.png ni w3.org', !eps.some((e) => /logo\.png|w3\.org/.test(e.url)), eps);

  await r.evaluate(() => { state.active = 'api'; renderTabs(); renderPanel(); document.body.classList.remove('full'); });
  await r.screenshot({ path: `${OUT}api-tab.png` });
  await r.evaluate(() => { const h = [...document.querySelectorAll('#panel h2')].find((x) => /Endpoints cités/.test(x.textContent)); h?.scrollIntoView(); });
  await r.screenshot({ path: `${OUT}api-tab-endpoints.png` });
  await r.evaluate(() => { const h = [...document.querySelectorAll('#panel h2')].find((x) => /JavaScript/.test(x.textContent)); h?.scrollIntoView(); });
  await r.screenshot({ path: `${OUT}api-tab-secrets.png` });

  // Mode actif : la spécification OpenAPI doit être trouvée, pas les catch-all HTML.
  await r.evaluate(() => document.getElementById('tg-active').click());
  await r.waitForFunction(() => !state.busy && state.settings.activeMode && state.raw.probes, { timeout: 30000, polling: 250 });
  const doc = await r.evaluate(() => state.raw.probes.apiDoc && { path: state.raw.probes.apiDoc.path, total: state.raw.probes.apiDoc.total });
  check('doc OpenAPI trouvée sur /openapi.json, 3 routes', doc?.path === '/openapi.json' && doc.total === 3, doc);
  await r.evaluate(() => { state.active = 'api'; renderTabs(); renderPanel(); });
  await r.evaluate(() => { document.getElementById('panel').scrollTop = 10000; });
  await r.screenshot({ path: `${OUT}api-tab-doc.png` });
  await r.evaluate(() => document.getElementById('tg-active').click());
} finally {
  console.log('errors', JSON.stringify(errors));
  await browser.close();
}
process.exit(failed || errors.length ? 1 : 0);
