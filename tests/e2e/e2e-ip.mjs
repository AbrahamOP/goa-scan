// IP affichée selon le type de chargement : réseau, cache (rechargement), bfcache (retour arrière).
// Attendu : toujours une IP, lue sur une connexion directe (ipInfo.source = 'direct').
import puppeteer from 'puppeteer-core';
const EXT = new URL('../../', import.meta.url).pathname;

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [EXT], args: ['--no-sandbox'] });
let failed = 0;
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  const base = `chrome-extension://${new URL(sw.url()).host}/popup.html`;
  const page = await browser.newPage();

  const scan = async (label) => {
    const r = await browser.newPage();
    await r.goto(base);
    const tabId = await r.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url === u)?.id, page.url());
    await r.goto(`${base}?tab=${tabId}`);
    await r.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
    const s = await r.evaluate(() => ({ ip: state.raw.ip, info: state.raw.ipInfo, hint: document.querySelector('#panel p.hint')?.textContent || null }));
    await r.close();
    const ok = !!s.ip && s.info?.source === 'direct';
    if (!ok) failed++;
    console.log(ok ? 'ok ' : 'KO ', label, page.url(), JSON.stringify(s));
  };

  await page.goto('https://example.com/', { waitUntil: 'networkidle2' }); await scan('réseau');
  await page.reload({ waitUntil: 'networkidle2' }); await scan('rechargement (cache)');
  await page.goto('https://en.wikipedia.org/wiki/Main_Page', { waitUntil: 'networkidle2' });
  await page.goBack({ waitUntil: 'networkidle2' }); await scan('retour arrière (bfcache)');

  // IP du chargement différente de la connexion directe : le rapport doit l'expliquer.
  const r = await browser.newPage();
  await r.goto(base);
  const hints = await r.evaluate(() => [
    ipHint({ ipInfo: { source: 'direct', load: { ip: '198.51.100.7', fromCache: true } } }),
    ipHint({ ipInfo: { source: 'direct', load: { ip: '198.51.100.7', fromCache: false } } }),
    ipHint({ ipInfo: { source: 'cache', load: null } }),
    ipHint({ ipInfo: { source: 'direct', load: null } }),
  ]);
  const ok = /198\.51\.100\.7.*cache/.test(hints[0]) && /CDN/.test(hints[1]) && /cache/.test(hints[2]) && hints[3] === null;
  if (!ok) failed++;
  console.log(ok ? 'ok ' : 'KO ', 'messages IP', JSON.stringify(hints, null, 1));
} finally { await browser.close(); }
process.exit(failed ? 1 : 0);
