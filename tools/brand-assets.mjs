// Visuels de présentation, tous tirés d'un même gabarit HTML rendu par Chromium :
//   store/banner.png          1280×400  en-tête du README (fond opaque : lisible en thème clair et sombre)
//   store/social-preview.png  1280×640  aperçu des liens GitHub (Settings → Social preview, à téléverser à la main)
//   store/promo-small.png      440×280  tuile promo du Chrome Web Store (obligatoire)
//   store/promo-marquee.png   1400×560  bannière « marquee » du Chrome Web Store (facultative)
// Polices : celles de l'extension (fonts/) + Fraunces italique (FRAUNCES=…, défaut ~/.fonts).
// Usage : node tools/brand-assets.mjs
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(root, 'store');
const fraunces = process.env.FRAUNCES || path.join(os.homedir(), '.fonts', 'Fraunces-Italic.ttf');
const font = (f) => pathToFileURL(path.join(root, 'fonts', f)).href;
const icon = fs.readFileSync(path.join(root, 'icons', 'icon.svg'), 'utf8').replace(/width="512" height="512"/, 'width="100%" height="100%"');

const TAGLINE = 'Every security signal of the page you’re on. Scored, explained, local.';
const CHECKS = ['TLS certificate', 'Security headers', 'Cookies', 'API calls', 'Secrets in JS', 'Vulnerable libraries'];
const FINDINGS = [
  ['CRITICAL', 'crit', 'Live Stripe secret key in JavaScript'],
  ['HIGH', 'high', 'Session cookie readable from JavaScript'],
  ['MEDIUM', 'med', 'Content-Security-Policy missing'],
  ['MEDIUM', 'med', 'jquery 1.12.4 — 4 known CVEs'],
  ['LOW', 'low', 'Referrer-Policy not set'],
];

const css = `
@font-face { font-family: JBM; src: url(${font('jbm-bold.woff2')}); font-weight: 700; }
@font-face { font-family: JBM; src: url(${font('jbm-regular.woff2')}); font-weight: 400; }
@font-face { font-family: Inter; src: url(${font('inter.woff2')}); font-weight: 100 900; }
@font-face { font-family: Fraunces; src: url(${pathToFileURL(fraunces).href}); font-style: italic; }
* { box-sizing: border-box; margin: 0; }
body { width: var(--w); height: var(--h); background: #0a1411; color: #e6f2ec; font-family: Inter, system-ui, sans-serif; overflow: hidden;
  background-image: radial-gradient(ellipse at 85% 50%, rgba(83,74,183,.16), transparent 60%), radial-gradient(ellipse at 10% 100%, rgba(29,158,117,.12), transparent 55%); }
.wrap { height: 100%; display: flex; align-items: center; gap: var(--gap); padding: 0 var(--pad); }
.id { flex: 1; min-width: 0; }
.brand { display: flex; align-items: center; gap: calc(var(--s) * 18px); }
.logo { width: calc(var(--s) * 84px); height: calc(var(--s) * 84px); flex: none; }
.word { font-family: JBM, monospace; font-weight: 700; font-size: calc(var(--s) * 64px); letter-spacing: -.01em; line-height: 1;
  background: linear-gradient(45deg, #3ad0a0, #8e84f0); -webkit-background-clip: text; color: transparent; }
.tag { font-family: Fraunces, Georgia, serif; font-style: italic; font-weight: 400; color: #b8cfc4; font-size: calc(var(--s) * 27px); line-height: 1.3; margin-top: calc(var(--s) * 22px); max-width: 17em; }
.chips { display: flex; flex-wrap: wrap; gap: calc(var(--s) * 8px); margin-top: calc(var(--s) * 26px); }
.chip { font-family: JBM, monospace; font-size: calc(var(--s) * 15px); color: #9ab8ab; border: 1px solid #1c2b24; background: #0e1a14; border-radius: 6px; padding: calc(var(--s) * 5px) calc(var(--s) * 10px); }
.card { width: calc(var(--s) * 470px); flex: none; background: #0e1a14; border: 1px solid #1c2b24; border-radius: 14px; padding: calc(var(--s) * 20px); }
.head { display: flex; align-items: center; gap: calc(var(--s) * 16px); margin-bottom: calc(var(--s) * 16px); }
.grade { width: calc(var(--s) * 58px); height: calc(var(--s) * 58px); border: 2px solid #e07a7a; border-radius: 10px; display: grid; place-items: center;
  font-family: JBM, monospace; font-weight: 700; font-size: calc(var(--s) * 30px); color: #e07a7a; }
.score { font-family: JBM, monospace; font-weight: 700; font-size: calc(var(--s) * 24px); } .score small { font-weight: 400; color: #9ab8ab; font-size: .6em; }
.host { font-family: JBM, monospace; font-size: calc(var(--s) * 14px); color: #9ab8ab; margin-top: 2px; }
.f { display: flex; align-items: center; gap: calc(var(--s) * 10px); border: 1px solid #1c2b24; border-radius: 8px; padding: calc(var(--s) * 8px) calc(var(--s) * 10px); margin-top: calc(var(--s) * 7px); font-size: calc(var(--s) * 15px); white-space: nowrap; overflow: hidden; }
.sev { font-family: JBM, monospace; font-weight: 700; font-size: calc(var(--s) * 11px); letter-spacing: .04em; border-radius: 4px; padding: 2px 6px; min-width: 6.4em; text-align: center; }
.crit { background: #e07a7a; color: #0a1411; } .high { border: 1px solid #e07a7a; color: #e07a7a; }
.med { border: 1px solid #8e84f0; color: #8e84f0; } .low { border: 1px solid #5d7268; color: #9ab8ab; }
/* tuile promo : logo + nom seulement */
.tile { width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; }
.tile .logo { width: 104px; height: 104px; } .tile .word { font-size: 44px; } .tile .tag { font-size: 17px; margin: 0; text-align: center; max-width: 20em; }
`;

const card = (n) => `<div class="card"><div class="head"><div class="grade">F</div><div><div class="score">18<small> /100</small></div><div class="host">https://shop.example</div></div></div>
${FINDINGS.slice(0, n).map(([l, c, t]) => `<div class="f"><span class="sev ${c}">${l}</span>${t}</div>`).join('')}</div>`;
const identity = (chips) => `<div class="id"><div class="brand"><div class="logo">${icon}</div><div class="word">Goa Scan</div></div>
<p class="tag">${TAGLINE}</p>${chips ? `<div class="chips">${CHECKS.map((c) => `<span class="chip">${c}</span>`).join('')}</div>` : ''}</div>`;

const ASSETS = [
  { file: 'banner.png', w: 1280, h: 400, s: .8, gap: 56, pad: 72, body: () => identity(true) + card(4) },
  { file: 'social-preview.png', w: 1280, h: 640, s: 1, gap: 64, pad: 80, body: () => identity(true) + card(5) },
  { file: 'promo-marquee.png', w: 1400, h: 560, s: 1, gap: 72, pad: 96, body: () => identity(true) + card(5) },
  { file: 'promo-small.png', w: 440, h: 280, s: 1, gap: 0, pad: 0, body: () => `<div class="tile"><div class="logo">${icon}</div><div class="word">Goa Scan</div><p class="tag">Web security, scored A–F. Local.</p></div>` },
];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'goa-scan-brand-'));
const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--allow-file-access-from-files'] });
try {
  const page = await browser.newPage();
  for (const a of ASSETS) {
    const html = path.join(tmp, `${a.file}.html`);
    fs.writeFileSync(html, `<!doctype html><meta charset="utf-8"><style>${css}</style><body style="--w:${a.w}px;--h:${a.h}px;--s:${a.s};--gap:${a.gap}px;--pad:${a.pad}px"><div class="wrap">${a.body()}</div>`);
    await page.setViewport({ width: a.w, height: a.h, deviceScaleFactor: 1 });
    await page.goto(pathToFileURL(html).href, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);
    const missing = await page.evaluate(() => [...document.fonts].filter((f) => f.status === 'error').map((f) => f.family));
    if (missing.length) console.warn(`${a.file} : polices non chargées → ${missing.join(', ')}`);
    await page.screenshot({ path: path.join(OUT, a.file), clip: { x: 0, y: 0, width: a.w, height: a.h } });
    console.log(a.file);
  }
} finally {
  await browser.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}
