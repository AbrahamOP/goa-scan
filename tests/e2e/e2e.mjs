import puppeteer from 'puppeteer-core';

const EXT = new URL('../../', import.meta.url).pathname;
const OUT = process.env.OUT || '/tmp/goa-scan-shots/';
await import('node:fs').then((fs) => fs.mkdirSync(OUT, { recursive: true }));
const TARGETS = [
  { name: 'fixture', url: 'http://127.0.0.1:8765/' },
  { name: 'example', url: 'https://example.com/' },
  { name: 'github', url: 'https://github.com/' },
];

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME || '/usr/bin/chromium',
  headless: true,
  pipe: true,
  enableExtensions: [EXT],
  args: ['--no-sandbox', '--window-size=1280,900'],
});
const errors = [];
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  const extId = new URL(sw.url()).host;
  console.log('extension', extId);
  const base = `chrome-extension://${extId}/popup.html`;

  for (const t of TARGETS) {
    const page = await browser.newPage();
    await page.goto(t.url, { waitUntil: 'networkidle2', timeout: 30000 });

    const report = await browser.newPage();
    report.on('pageerror', (e) => errors.push(`${t.name}: ${e.message}`));
    report.on('console', (m) => { if (m.type() === 'error') errors.push(`${t.name} console: ${m.text()}`); });
    await report.goto(base);
    const tabId = await report.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url?.startsWith(u))?.id, t.url);
    await report.setViewport({ width: 460, height: 590 });
    await report.goto(`${base}?tab=${tabId}`);
    await report.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
    // Rendu « popup » : on retire la mise en page pleine largeur.
    await report.evaluate(() => document.body.classList.remove('full'));

    const summary = await report.evaluate(() => ({
      grade: state.report.grade, score: state.report.score, headerSource: state.raw.headerSource,
      requests: state.raw.net?.requests ?? null, ip: state.raw.ip, dom: !!state.raw.dom,
      failing: state.report.findings.filter((f) => !f.ok).map((f) => `${f.sev}:${f.id}`),
      tech: state.report.tech.map((x) => `${x.name}${x.version ? ' ' + x.version : ''}`),
      cookies: state.raw.cookies.map((c) => c.name),
    }));
    console.log(t.name, JSON.stringify(summary, null, 1));

    await report.screenshot({ path: `${OUT}${t.name}-summary.png` });
    if (t.name === 'fixture') {
      const tabs = await report.$$('#tabs button');
      const names = ['summary', 'headers', 'cookies', 'content', 'network'];
      for (let i = 1; i < tabs.length; i++) {
        await (await report.$$('#tabs button'))[i].click();
        await report.screenshot({ path: `${OUT}${t.name}-${names[i]}.png` });
      }
      // Ouvre un constat pour vérifier le détail + correctif.
      await (await report.$$('#tabs button'))[0].click();
      await report.evaluate(() => document.querySelector('details.finding')?.setAttribute('open', ''));
      await report.screenshot({ path: `${OUT}${t.name}-open.png` });
    }
    if (t.name === 'github') {
      await report.evaluate(() => document.body.classList.add('full'));
      await report.setViewport({ width: 1100, height: 900 });
      await report.screenshot({ path: `${OUT}${t.name}-full.png`, fullPage: true });
    }
    await report.close();
    await page.close();
  }
} finally {
  console.log('errors', JSON.stringify(errors, null, 1));
  await browser.close();
}
