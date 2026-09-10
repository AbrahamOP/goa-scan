// Captures pour la fiche du Chrome Web Store, au format exigé 1280×800.
// Prérequis : python3 tests/e2e/fixture-active.py &  (pour la cible locale riche en constats)
// Usage : node tools/store-shots.mjs   → store/screenshots/*.png
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'store', 'screenshots');
fs.mkdirSync(OUT, { recursive: true });
const W = 1280, H = 800;

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [root], args: ['--no-sandbox', `--window-size=${W},${H}`] });
try {
  const swT = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  await (await swT.worker()).evaluate(() => ready);
  const base = `chrome-extension://${new URL(swT.url()).host}/popup.html`;

  const shot = async (url, name, tab) => {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const r = await browser.newPage();
    await r.goto(base);
    const tabId = await r.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url === u)?.id, url);
    await r.setViewport({ width: W, height: H, deviceScaleFactor: 1 });
    await r.goto(`${base}?tab=${tabId}`);
    await r.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
    await r.evaluate((t) => { document.body.classList.add('full'); if (t) { state.active = t; renderTabs(); renderPanel(); } }, tab);
    await r.evaluate(() => { document.getElementById('panel').scrollTop = 0; window.scrollTo(0, 0); });
    await r.screenshot({ path: path.join(OUT, `${name}.png`), clip: { x: 0, y: 0, width: W, height: H } });
    await r.close(); await page.close();
    console.log(name);
  };

  await shot('http://127.0.0.1:8766/', '1-synthese', 'summary');
  await shot('https://github.com/', '2-certificat', 'cert');
  await shot('http://127.0.0.1:8766/', '3-code-js', 'jscode');
  await shot('http://127.0.0.1:8766/', '4-api', 'api');
} finally {
  await browser.close();
}
