// Variante de test : copie de l'extension avec « debugger » en permission obligatoire
// (la demande optionnelle exige un clic humain dans une boîte de dialogue Chrome).
import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
const SRC = new URL('../../', import.meta.url).pathname;
const EXT = '/tmp/goa-scan-ext-cert/';
const OUT = process.env.OUT || '/tmp/goa-scan-shots/';
fs.mkdirSync(OUT, { recursive: true });
fs.rmSync(EXT, { recursive: true, force: true });
fs.cpSync(SRC, EXT, { recursive: true, filter: (p) => !p.includes('/.git') && !p.includes('/tests') });
const m = JSON.parse(fs.readFileSync(EXT + '/manifest.json'));
m.permissions.push('debugger'); delete m.optional_permissions;
fs.writeFileSync(EXT + '/manifest.json', JSON.stringify(m));

const TARGETS = ['https://github.com/', 'https://expired.badssl.com/', 'https://wrong.host.badssl.com/', 'https://self-signed.badssl.com/', 'https://tls-v1-2.badssl.com:1012/', 'https://sha256.badssl.com/'];
const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [EXT], args: ['--no-sandbox'] });
const errors = [];
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  const base = `chrome-extension://${new URL(sw.url()).host}/popup.html`;
  for (const url of TARGETS) {
    const name = new URL(url).hostname.split('.')[0];
    const page = await browser.newPage();
    try { await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 }); } catch (e) { console.log(name, 'goto:', e.message.split('\n')[0]); }
    const r = await browser.newPage();
    r.on('pageerror', (e) => errors.push(`${name}: ${e.message}`));
    await r.goto(base);
    const tabId = await r.evaluate(async (u) => (await chrome.tabs.query({})).find((x) => x.url?.startsWith(u))?.id, url);
    if (!tabId) { console.log(name, 'onglet introuvable'); await r.close(); await page.close(); continue; }
    await r.setViewport({ width: 460, height: 590 });
    await r.goto(`${base}?tab=${tabId}`);
    await r.waitForFunction(() => typeof state !== 'undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
    await r.evaluate(() => { document.body.classList.remove('full'); state.active = 'cert'; renderTabs(); renderPanel(); });
    const s = await r.evaluate(() => ({
      grade: state.report.grade, score: state.report.score, tls: state.raw.tls && {
        status: state.raw.tls.status, error: state.raw.tls.error, protocol: state.raw.tls.protocol, group: state.raw.tls.group,
        cipher: state.raw.tls.cipher, networkError: state.raw.tls.networkError,
        chain: (state.raw.tls.chain || []).map((c) => `${c.subject.cn} | ${c.key.type}${c.key.bits} | ${c.sigAlg} | ${c.validation || ''} | san:${c.san.length}`),
      },
      cert: state.report.findings.filter((f) => f.cat === 'certificate').map((f) => `${f.ok ? 'ok' : f.sev}: ${f.title}`),
    }));
    console.log(name, JSON.stringify(s, null, 1));
    await r.screenshot({ path: `${OUT}cert-${name}.png` });
    if (name === 'github') { await r.evaluate(() => document.querySelector('.certcard details')?.setAttribute('open', '')); await r.evaluate(() => document.getElementById('panel').scrollTop = 400); await r.screenshot({ path: `${OUT}cert-github-chain.png` }); }
    await r.close(); await page.close();
  }
} finally { console.log('errors', JSON.stringify(errors)); await browser.close(); }
