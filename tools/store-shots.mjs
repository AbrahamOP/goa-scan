// Captures pour la fiche du Chrome Web Store, au format exigé 1280×800.
// Prérequis : python3 tests/e2e/fixture-active.py &  (pour la cible locale riche en constats)
// Usage : node tools/store-shots.mjs   → store/screenshots/*.png + store/readme/*.png (popups pour le README)
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'store', 'screenshots');
fs.mkdirSync(OUT, { recursive: true });
const W = 1280, H = 800;

// Copie avec « debugger » obligatoire : la demande optionnelle exige un clic humain, et sans
// elle l'onglet Certificat n'affiche que le bouton d'activation.
const EXT = fs.mkdtempSync(path.join(os.tmpdir(), 'goa-scan-shots-'));
fs.cpSync(root, EXT, { recursive: true, filter: (p) => !/\/(\.git|tests|store|dist|node_modules)(\/|$)/.test(p.slice(root.length)) });
const m = JSON.parse(fs.readFileSync(path.join(EXT, 'manifest.json'), 'utf8'));
m.permissions.push('debugger'); delete m.optional_permissions;
fs.writeFileSync(path.join(EXT, 'manifest.json'), JSON.stringify(m));

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [EXT], args: ['--no-sandbox', `--window-size=${W},${H}`] });
try {
  const swT = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  await (await swT.worker()).evaluate(() => ready);
  const base = `chrome-extension://${new URL(swT.url()).host}/popup.html`;

  const shot = async (url, name, tab, { w = W, h = H, dsf = 1, full = true, dir = OUT } = {}) => {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const r = await browser.newPage();
    await r.goto(base);
    const tabId = await r.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url === u)?.id, url);
    await r.setViewport({ width: w, height: h, deviceScaleFactor: dsf });
    await r.goto(`${base}?tab=${tabId}`);
    await r.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
    await r.evaluate((t, full) => { document.body.classList.toggle('full', full); if (t) { state.active = t; renderTabs(); renderPanel(); } }, tab, full);
    if (tab === 'cert') await r.evaluate(() => document.querySelector('.certcard details')?.setAttribute('open', ''));
    await r.evaluate(() => { document.getElementById('panel').scrollTop = 0; window.scrollTo(0, 0); });
    await r.screenshot({ path: path.join(dir, `${name}.png`), clip: { x: 0, y: 0, width: w, height: h } });
    await r.close(); await page.close();
    console.log(name);
  };

  await shot('http://127.0.0.1:8766/', '1-synthese', 'summary');
  await shot('https://github.com/', '2-certificat', 'cert');
  await shot('http://127.0.0.1:8766/', '3-code-js', 'jscode');
  await shot('http://127.0.0.1:8766/', '4-api', 'api');

  // Popups à taille réelle (460×600, rendu ×2) assemblés par tools/brand-assets.mjs en store/showcase.png.
  const pop = { w: 460, h: 600, dsf: 2, full: false, dir: path.join(root, 'store', 'readme') };
  fs.mkdirSync(pop.dir, { recursive: true });
  await shot('http://127.0.0.1:8766/', 'summary', 'summary', pop);
  await shot('https://github.com/', 'cert', 'cert', pop);
  await shot('http://127.0.0.1:8766/', 'jscode', 'jscode', pop);
} finally {
  await browser.close();
  fs.rmSync(EXT, { recursive: true, force: true });
}
